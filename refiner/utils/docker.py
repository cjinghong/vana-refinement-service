import os
import uuid
import json
import io
import tarfile
from datetime import datetime

import docker
import requests
import vana

from refiner.errors.exceptions import ContainerTimeoutError
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import DockerRun, Output
from refiner.utils.docker_cache import DockerImageCache

# Initialize the image cache as a module-level singleton
_image_cache = None


def get_image_cache() -> DockerImageCache:
    """Get or create the Docker image cache singleton."""
    global _image_cache
    if _image_cache is None:
        cache_dir = os.getenv('DOCKER_IMAGE_CACHE_DIR', '/var/cache/vana/docker-images')
        max_cache_size_gb = float(os.getenv('DOCKER_IMAGE_CACHE_SIZE_GB', '20.0'))
        ttl_days = int(os.getenv('DOCKER_IMAGE_CACHE_TTL_DAYS', '7'))
        _image_cache = DockerImageCache(
            cache_dir=cache_dir,
            max_cache_size_gb=max_cache_size_gb,
            ttl_days=ttl_days
        )
    return _image_cache


def get_docker_client():
    client = None
    try:
        client = docker.from_env()
        vana.logging.debug(f"Docker client initialized successfully. {client.version()}")
    except docker.errors.DockerException as e:
        vana.logging.error(f"Error initializing Docker client: {e}")
        raise Exception("Docker client is not initialized")

    if client is None:
        raise Exception("Docker client is not initialized")
    return client


def run_signed_container(
    image_url: str,
    environment: dict,
    input_file_path: str,
    request_id: str
) -> DockerRun:
    """
    Runs a container with the given image and copies the input file directly into it.
    
    Args:
        image_url: URL of the container image.
        environment: Environment variables to pass to the container.
        input_file_path: Path to the file to copy into the container's /input directory.
        request_id: Request ID for logging context.

    Returns:
        DockerRun: Result of running the container including logs, exit code, and parsed output data.
    """
    if request_id:
        request_id_context.set(request_id)

    client = get_docker_client()
    cache = get_image_cache()

    # Get container timeout from environment variable (default 10 seconds)
    container_timeout = int(os.getenv('CONTAINER_TIMEOUT_SECONDS', '60'))
    vana.logging.debug(f"Container timeout set to {container_timeout} seconds")

    vana.logging.debug(f"Getting image from cache or downloading: {image_url}")
    image_tag = cache.get_image(image_url)

    if not image_tag:
        raise ValueError(f"Failed to get Docker image from {image_url}")

    # Generate a unique container name
    container_name = f"refinement-{request_id}-{image_tag.split('/')[-1].split(':')[0]}-{uuid.uuid4().hex[:8]}"
    docker_run = DockerRun(
        container_name=container_name,
        exit_code=None,
        logs="",
        started_at=datetime.now(),
        terminated_at=None,
        output_data=None
    )

    input_volume_name = f"input-{uuid.uuid4().hex}"
    output_volume_name = f"output-{uuid.uuid4().hex}"
    input_volume = client.volumes.create(input_volume_name)
    output_volume = client.volumes.create(output_volume_name)
    container = None

    try:
        volumes = {
            input_volume_name: {'bind': '/input', 'mode': 'rw'},
            output_volume_name: {'bind': '/output', 'mode': 'rw'},
        }
        vana.logging.info(f"Using volumes: {volumes}")

        container = client.containers.create(
            image=image_tag,
            name=container_name,
            environment=environment,
            volumes=volumes,
            detach=True,
        )

        container.start()
        vana.logging.info(f"Started container {container_name} from image {image_tag}")
        
        # Copy the input file to the container
        with open(input_file_path, 'rb') as file_data:
            file_size = os.path.getsize(input_file_path)
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                file_info = tarfile.TarInfo(name=os.path.basename(input_file_path))
                file_info.size = file_size
                tar.addfile(file_info, file_data)
            tar_buffer.seek(0)
            archive_size = len(tar_buffer.getvalue())
            client.api.put_archive(container.id, '/input', tar_buffer.getvalue())
        vana.logging.info(f"Successfully copied file to container's /input directory ({file_size} bytes, archive size: {archive_size} bytes)")

        try:
            result = container.wait(timeout=container_timeout)
            docker_run.exit_code = result.get('StatusCode', -1)
            vana.logging.info(f"Container {container_name} finished with exit code {docker_run.exit_code}")
        except requests.exceptions.ReadTimeout:
            vana.logging.error(f"Container {container_name} timed out after {container_timeout} seconds. Killing container.")
            try: container.kill()
            except docker.errors.APIError as kill_e: vana.logging.error(f"Error killing timed-out container {container_name}: {kill_e}")
            docker_run.exit_code = 137
            raise ContainerTimeoutError(container_name=container_name, timeout=container_timeout)
        except Exception as e:
            vana.logging.error(f"Unexpected error waiting for container {container_name}: {str(e)}")
            docker_run.exit_code = -1
            raise
        finally:
             docker_run.terminated_at = datetime.now()

        # Retrieve logs after waiting/timeout
        try:
            docker_run.logs = container.logs().decode('utf-8', errors='replace')
            vana.logging.debug(f"Container {container_name} logs retrieved.")
        except docker.errors.APIError as log_e:
            vana.logging.error(f"Failed to retrieve logs for container {container_name}: {log_e}")
            docker_run.logs = "<Failed to retrieve logs>"

        # Retrieve output.json from the output volume
        if docker_run.exit_code == 0:
            vana.logging.info(f"Attempting to retrieve output.json from volume {output_volume_name}")
            output_content = None
            try:
                # Run a temporary alpine container to cat the file from the volume
                output_content_bytes = client.containers.run(
                    image='alpine:latest',
                    command=f'cat /volume_data/output.json',
                    volumes={output_volume_name: {'bind': '/volume_data', 'mode': 'ro'}}, # Mount read-only
                    remove=True, # Automatically remove the container when done
                    stdout=True,
                    stderr=True
                )
                output_content = output_content_bytes.decode('utf-8').strip()
                vana.logging.info(f"Successfully retrieved content from output.json")
                vana.logging.debug(f"output.json content: \n{output_content}")
            except docker.errors.ContainerError as cat_err:
                # This happens if the command fails (e.g., file not found)
                vana.logging.warning(f"Could not retrieve output.json: Command failed in helper container. Stderr: {cat_err.stderr.decode('utf-8', errors='replace')}")
            except Exception as read_err:
                vana.logging.error(f"Unexpected error retrieving output.json: {read_err}")

            # Parse the content if retrieved
            if output_content:
                try:
                    parsed_data = json.loads(output_content)
                    # Validate and store using the Pydantic model
                    docker_run.output_data = Output(**parsed_data)
                    vana.logging.info(f"Successfully parsed output.json into Output model.")
                except json.JSONDecodeError as json_err:
                    vana.logging.error(f"Failed to parse JSON from output.json: {json_err}")
                    docker_run.logs += "\n[REFINER_ERROR] Failed to parse output.json content."
                except Exception as pydantic_err: # Catch potential Pydantic validation errors
                     vana.logging.error(f"Failed to validate output.json against Output model: {pydantic_err}")
                     docker_run.logs += f"\n[REFINER_ERROR] Failed to validate output.json content: {pydantic_err}"
        else:
             vana.logging.warning(f"Skipping output.json retrieval as container exit code was {docker_run.exit_code}")

        return docker_run

    except Exception as e:
        vana.logging.error(f"Error in run_signed_container setup/execution for {container_name}: {str(e)}")
        if docker_run.exit_code is None: docker_run.exit_code = -1
        raise

    finally:
        # Clean up main container and output volume
        try:
            if container:
                vana.logging.info(f"Removing container: {container_name}")
                container.remove(force=True)
        except docker.errors.NotFound:
             vana.logging.info(f"Container {container_name} already removed during cleanup.")
        except Exception as e:
            vana.logging.error(f"Error removing container {container_name}: {str(e)}")

        try:
            if output_volume:
                vana.logging.info(f"Removing output volume: {output_volume_name}")
                output_volume.remove(force=True)
        except docker.errors.NotFound:
             vana.logging.info(f"Output volume {output_volume_name} already removed during cleanup.")
        except Exception as e:
            vana.logging.error(f"Error removing output volume {output_volume_name}: {str(e)}")
