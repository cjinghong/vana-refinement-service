import os
import shutil
import uuid

import vana
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from refiner.errors.exceptions import FileDecryptionError, FileDownloadError, RefinementBaseException
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse
from refiner.utils.cryptography import decrypt_file, ecies_encrypt
from refiner.utils.docker import run_signed_container
from refiner.utils.files import download_file, detect_file_type

def refine(
        client: vana.Client,
        request: RefinementRequest,
        request_id: str = None
) -> RefinementResponse:
    # Set request ID in context if provided
    if request_id:
        request_id_context.set(request_id)

    # Get file info from chain
    file_info = client.get_file(request.file_id)
    if not file_info:
        raise RefinementBaseException(
            status_code=404,
            message=f"File {request.file_id} not found",
            error_code="FILE_NOT_FOUND"
        )

    (id, ownerAddress, url, addedAtBlock) = file_info
    vana.logging.info(f"Processing file ID: {id}, url: {url}, ownerAddress: {ownerAddress}")

    encrypted_file_path = None
    decrypted_file_path = None
    temp_dir = None  # This will store the base temp dir (parent of 'input')

    try:
        # 1. Download the encrypted file
        vana.logging.info("Starting file download...")
        encrypted_file_path = download_file(url)
        temp_dir = os.path.dirname(encrypted_file_path)  # Get the base temporary directory
        encrypted_file_size = os.path.getsize(encrypted_file_path) if os.path.exists(encrypted_file_path) else 0
        vana.logging.info(f"Successfully downloaded encrypted file to: {encrypted_file_path} ({encrypted_file_size} bytes)")
        
        # Check if the downloaded file exists and has content
        if not os.path.exists(encrypted_file_path) or encrypted_file_size == 0:
            raise FileDownloadError(f"Downloaded file is empty or does not exist: {encrypted_file_path}")

        # 2. Decrypt the file (will be placed in temp_dir/input/decrypted_file...)
        vana.logging.info("Starting file decryption...")
        decrypted_file_path = decrypt_file(encrypted_file_path, request.encryption_key)
        decrypted_file_size = os.path.getsize(decrypted_file_path) if os.path.exists(decrypted_file_path) else 0
        # The path to the directory containing the decrypted file is needed for mounting
        input_dir_host_path = os.path.dirname(decrypted_file_path)
        vana.logging.info(f"Host path for input mount: {input_dir_host_path} (decrypted file: {decrypted_file_size} bytes)")
        
        # Check if the decrypted file exists and has content
        if not os.path.exists(decrypted_file_path) or decrypted_file_size == 0:
            raise FileDecryptionError(f"Decrypted file is empty or does not exist: {decrypted_file_path}")
        
        # Detect + correct the decrypted file type based on the content
        detected_extension = detect_file_type(decrypted_file_path)
        current_extension = os.path.splitext(decrypted_file_path)[1]

        if detected_extension != current_extension:
            new_path = os.path.splitext(decrypted_file_path)[0] + detected_extension
            os.rename(decrypted_file_path, new_path)
            decrypted_file_path = new_path
            vana.logging.info(f"Decrypted file type detected as {detected_extension} based on content")

        if os.getenv('CHAIN_NETWORK') == 'moksha' and os.getenv('DEBUG_FILES_DIR'):
            debug_dir = os.getenv('DEBUG_FILES_DIR')
            os.makedirs(debug_dir, exist_ok=True)
            debug_file_path = os.path.join(debug_dir, os.path.basename(decrypted_file_path)) + uuid.uuid4().hex[:8]
            shutil.copy2(decrypted_file_path, debug_file_path)
            vana.logging.info(f"Copied decrypted file to debug directory: {debug_file_path}")

        # 3. Look up the refiner instructions
        refiner = client.get_refiner(request.refiner_id)
        dlp_id = refiner.get('dlp_id', 0)
        if dlp_id == 0:
            raise RefinementBaseException(
                status_code=404,
                message=f"Refiner with ID {request.refiner_id} not found",
                error_code="REFINER_NOT_FOUND"
            )
        vana.logging.info(f"Refiner for refiner ID {request.refiner_id}: {refiner}")

        dlp_pub_key = client.get_dlp_pub_key(dlp_id)
        if not dlp_pub_key:
            raise RefinementBaseException(
                status_code=404,
                message=f"DLP public key for refiner {request.refiner_id} and DLP ID {dlp_id} not found",
                error_code="REFINER_DLP_PUBLIC_KEY_NOT_FOUND"
            )
        vana.logging.info(f"DLP public key for DLP ID {dlp_id}: {dlp_pub_key}")

        # 4. Generate Refinement Encryption Key (REK) from the user's original encryption key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'query-engine',
            backend=default_backend()
        )
        master_key_bytes = bytes.fromhex(request.encryption_key.removeprefix('0x'))
        refinement_encryption_key = '0x' + hkdf.derive(master_key_bytes).hex()
        encrypted_refinement_encryption_key, ephemeral_sk, nonce = ecies_encrypt(dlp_pub_key,
                                                                                 refinement_encryption_key.encode())
        vana.logging.info(f"Encrypted encryption key: {encrypted_refinement_encryption_key.hex()}")

        # 5. Run the refiner Docker container
        # Ensure environment variables are strings
        environment = {
            **request.env_vars,
            "FILE_ID": request.file_id,
            "FILE_URL": url,
            "FILE_OWNER_ADDRESS": ownerAddress,
            "REFINEMENT_ENCRYPTION_KEY": refinement_encryption_key,
            "INPUT_DIR": "/input",
            "OUTPUT_DIR": "/output"
        }

        docker_run_result = run_signed_container(
            image_url=refiner.get('refinement_instruction_url'),
            environment=environment,
            input_file_path=decrypted_file_path,
            request_id=request_id
        )
        vana.logging.info(
            f"Refiner Docker run result (Exit Code: {docker_run_result.exit_code}):\n{docker_run_result.logs}")

        if docker_run_result.exit_code != 0:
            raise RefinementBaseException(
                status_code=500,
                message=f"Refiner container failed with exit code {docker_run_result.exit_code}",
                error_code="REFINER_CONTAINER_FAILED",
                details={"logs": docker_run_result.logs[-1000:]}  # Include last 1000 chars of logs
            )
        vana.logging.info(f"Refined file URL: {docker_run_result.output_data.refinement_url}")

        if not docker_run_result.output_data and not docker_run_result.output_data.refinement_url:
            raise RefinementBaseException(
                status_code=400,
                message="Refiner container did not output a refinement URL",
                error_code="REFINER_CONTAINER_NO_OUTPUT"
            )

        # 6. Add refinement to the data registry
        
        # Ensure the refinement URL is a valid URL and the file is accessible
        try:
            vana.logging.info(f"Validating refinement URL: {docker_run_result.output_data.refinement_url}")
            validation_file_path = download_file(docker_run_result.output_data.refinement_url)
            validation_file_size = os.path.getsize(validation_file_path) if os.path.exists(validation_file_path) else 0
            vana.logging.info(f"Successfully validated refinement URL, file size: {validation_file_size} bytes")
            
            # Clean up the validation file
            if validation_file_path and os.path.exists(validation_file_path):
                try:
                    validation_temp_dir = os.path.dirname(validation_file_path)
                    if os.path.isdir(validation_temp_dir):
                        shutil.rmtree(validation_temp_dir)
                        vana.logging.info(f"Cleaned up validation temporary directory: {validation_temp_dir}")
                except Exception as cleanup_e:
                    vana.logging.warning(f"Failed to clean up validation temporary directory: {cleanup_e}")
                    
            if validation_file_size == 0:
                raise RefinementBaseException(
                    status_code=400,
                    message="Refinement URL points to an empty file",
                    error_code="REFINEMENT_URL_EMPTY_FILE"
                )
        except FileDownloadError as e:
            vana.logging.error(f"Refinement URL validation failed: {e.details.get('error', str(e))}")
            raise RefinementBaseException(
                status_code=400,
                message=f"Refinement URL is not accessible: {e.details.get('error', str(e))}",
                error_code="REFINEMENT_URL_INVALID",
                details={"refinement_url": docker_run_result.output_data.refinement_url}
            )
        except Exception as e:
            vana.logging.error(f"Unexpected error during refinement URL validation: {e}")
            raise RefinementBaseException(
                status_code=500,
                message=f"Failed to validate refinement URL: {str(e)}",
                error_code="REFINEMENT_URL_VALIDATION_ERROR",
                details={"refinement_url": docker_run_result.output_data.refinement_url}
            )
        
        # Write the refinement to the data registry
        transaction_hash, transaction_receipt = client.add_refinement_with_permission(
            file_id=request.file_id,
            refiner_id=request.refiner_id,
            url=docker_run_result.output_data.refinement_url,
            account=os.getenv('QUERY_ENGINE_ACCOUNT'),
            key=encrypted_refinement_encryption_key.hex()
        )
        vana.logging.info(
            f"Refinement added to the data registry with transaction hash: {transaction_hash.hex()} and receipt: {transaction_receipt}")

        return RefinementResponse(
            add_refinement_tx_hash=transaction_hash.hex()
        )

    except FileDownloadError as e:
        vana.logging.error(f"File download failed for file ID {request.file_id}, URL {url}: {e.details.get('error', str(e))}")
        raise RefinementBaseException(
            status_code=500,
            message=f"Failed to download file: {e.details.get('error', str(e))}",
            error_code="FILE_DOWNLOAD_FAILED",
            details={"file_id": request.file_id, "url": url}
        )
    except FileDecryptionError as e:
        error_msg = e.details.get('error', 'Invalid encryption key or corrupted file')
        vana.logging.error(f"File decryption failed for file ID {request.file_id}: {error_msg}")
        raise RefinementBaseException(
            status_code=400,
            message=f"Failed to decrypt file: {error_msg}",
            error_code="FILE_DECRYPTION_FAILED",
            details={"file_id": request.file_id, "reason": "Invalid encryption key or corrupted file"}
        )
    except Exception as e:
        vana.logging.exception(f"An unexpected error occurred during refinement for file ID {request.file_id}: {e}")
        raise RefinementBaseException(
            status_code=500,
            message=f"An internal error occurred during refinement: {str(e)}",
            error_code="REFINEMENT_PROCESSING_ERROR",
            details={"file_id": request.file_id}
        )
    finally:
        if temp_dir and os.path.isdir(temp_dir):
            vana.logging.info(f"Cleaning up temporary directory: {temp_dir}")
            try:
                shutil.rmtree(temp_dir)
                vana.logging.info(f"Successfully removed temporary directory: {temp_dir}")
            except Exception as e:
                vana.logging.error(f"Failed to clean up temporary directory {temp_dir}: {e}")
