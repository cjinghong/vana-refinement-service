# Vana Refinement Service

## Overview

The Vana Refinement Service is a crucial component of the Vana ecosystem's data ingress pipeline. It is hosted by Vana within a Trusted Execution Environment (TEE), but also designed to be self-hostable by Data Liquidity Pools (DLPs)

This service orchestrates the execution of Data Refiner Docker images: https://github.com/vana-com/vana-data-refinement-template. Its primary goal is to transform raw, encrypted data submitted by data contributors into standardized and query-ready datasets suitable for indexing by the Vana Query Engine.

## Workflow

In the Vana Data Access Layer, raw data undergoes refinement to ensure quality, structure, and security before decentralized storage and indexing. The Refinement Service facilitates this by:

1.  **Trigger Refinement:** After a successful Proof-of-Contribution (PoC) run for a new data point, the DLP sends a request to the Refinement Service API (`/refine`).
2.  **Data Retrieval:** The service uses the `file_id` and `encryption_key` to download the raw encrypted file from its storage location.
3.  **Key Generation:** It generates the Refinement Encryption Key (REK) from the provided `encryption_key`.
4.  **Container Execution:** The service looks up the Data Refiner instructions (Docker image URL) using the `refiner_id` in the Data Refiner Registry contract. It then runs this Docker container, injecting the raw data, and REK as an environment variable.
5.  **In-Container Processing:** The Data Refiner container:
    *   Performs normalization and optional masking according to DLP-defined logic.
    *   Encrypts the refined data using the provided REK.
    *   Uploads the final encrypted, refined data to IPFS.
    *   Outputs the resulting IPFS CID.
6.  **Registry Update:** The Refinement Service receives the IPFS CID from the container and calls the `addRefinementWithPermission` function on the Vana Data Registry contract, associating the refined data CID with the original `file_id`, and granting the Vana Query Engine permission to access the refined data point.
7.  **Response:** The service returns the transaction hash of the `addRefinementWithPermission` call to the DLP.

## API

### `POST /refine`

Triggers the refinement process for a specific file using a specific refiner definition.

**Request Body:**

```json
{
  "file_id": 1234,
  "encryption_key": "0xabcd1234...",
  "refiner_id": 12,
  "env_vars": {
    "PINATA_API_KEY": "abc123",
    "PINATA_API_SECRET": "efg456"
  }
}
```

*   `file_id` (integer): The ID of the file in the Data Registry.
*   `encryption_key` (string): The symmetric key originally used to encrypt the file (e.g., a signature derived via `personal_sign`).
*   `refiner_id` (integer): The ID registered in the Data Refiner Registry, used to look up the refinement instructions (Docker image URL and schema).

**Response Body (Success - 200 OK):**

```json
{
  "add_refinement_tx_hash": "0x1234..."
}
```

*   `add_refinement_tx_hash` (string): The transaction hash for the `addRefinementWithPermission` call made to the Data Registry contract.

## Getting Started

### Prerequisites

*   Docker & Docker Compose
*   Python >= 3.10, < 3.13
*   Poetry (`pip install poetry`)
*   Access to a Vana Network RPC endpoint
*   `.env` file configured

**(Note:** Ensure the `.env` file is included in your `.gitignore` to avoid committing secrets.)

### Running Locally (Docker Compose)

The easiest way to run the service locally is using Docker Compose:

1.  **Build & Start:**
    ```bash
    docker-compose up --build
    ```

2.  **Access:** The API will be available at `http://localhost:8000`.

3.  **Stop:**
    ```bash
    docker-compose down
    ```

## Self-Hosting

While Vana provides a hosted instance, DLPs can self-host the Refinement Service. Follow the "Running Locally" instructions on the target machine. Ensure the host environment has Docker installed and running, and the necessary network access (e.g., to Vana RPC, IPFS). It is highly recommended to run the service within a TEE for production deployments.

DLP owners must whitelist the accounts associated with their self-hosted Refinement Services to allow them to submit `addRefinementWithPermission` transactions. This can be done by calling the `addRefinementService` function on the Vana Data Refiner Registry contract at address `0x93c3EF89369fDcf08Be159D9DeF0F18AB6Be008c`.

## License

[MIT License](LICENSE)
