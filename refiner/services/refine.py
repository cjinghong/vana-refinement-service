import os
import shutil

import vana
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from refiner.errors.exceptions import FileDecryptionError, FileDownloadError, RefinementBaseException
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse
from refiner.utils.cryptography import decrypt_file, ecies_encrypt
from refiner.utils.docker import run_signed_container
from refiner.utils.files import download_file


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
        vana.logging.info(f"Successfully downloaded encrypted file to: {encrypted_file_path}")

        # 2. Decrypt the file (will be placed in temp_dir/input/decrypted_file...)
        vana.logging.info("Starting file decryption...")
        decrypted_file_path = decrypt_file(encrypted_file_path, request.encryption_key)
        # The path to the directory containing the decrypted file is needed for mounting
        input_dir_host_path = os.path.dirname(decrypted_file_path)
        vana.logging.info(f"Host path for input mount: {input_dir_host_path}")

        # 3. Look up the refiner instructions
        refiner = client.get_refiner(request.refiner_id)
        if refiner.get('dlp_id', 0) == 0:
            raise RefinementBaseException(
                status_code=404,
                message=f"Refiner with ID {request.refiner_id} not found",
                error_code="REFINER_NOT_FOUND"
            )
        vana.logging.info(f"Refiner for refiner ID {request.refiner_id}: {refiner}")

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
        encrypted_refinement_encryption_key, ephemeral_sk, nonce = ecies_encrypt(refiner.get('public_key'),
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

        # 6. Add refinement to the data registry
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
        vana.logging.error(f"File download failed for file ID {request.file_id}, URL {url}: {e.error}")
        raise RefinementBaseException(
            status_code=500,
            message=f"Failed to download file: {e.error}",
            error_code="FILE_DOWNLOAD_FAILED",
            details={"file_id": request.file_id, "url": url}
        )
    except FileDecryptionError as e:
        vana.logging.error(f"File decryption failed for file ID {request.file_id}: {e.error}")
        raise RefinementBaseException(
            status_code=500,
            message=f"Failed to decrypt file: {e.error}",
            error_code="FILE_DECRYPTION_FAILED",
            details={"file_id": request.file_id}
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
