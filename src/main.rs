use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::{instruction as token_instruction, ID as TOKEN_PROGRAM_ID};
use std::str::FromStr;
use tower_http::cors::CorsLayer;
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("Invalid public key: {0}")]
    InvalidPubkey(String),
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Missing required fields")]
    MissingFields,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid addresses: {0}")]
    InvalidAddresses(String),
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(msg: String) -> ApiResponse<T> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(msg),
        }
    }
}

// Request/Response structures
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Helper functions
fn validate_pubkey(key: &str) -> Result<Pubkey, ServerError> {
    Pubkey::from_str(key).map_err(|_| ServerError::InvalidPubkey(key.to_string()))
}

fn validate_keypair(secret: &str) -> Result<Keypair, ServerError> {
    let secret_bytes = bs58::decode(secret)
        .into_vec()
        .map_err(|_| ServerError::InvalidSecretKey)?;
    
    if secret_bytes.len() != 64 {
        return Err(ServerError::InvalidSecretKey);
    }
    
    Keypair::from_bytes(&secret_bytes).map_err(|_| ServerError::InvalidSecretKey)
}

fn instruction_to_response(instruction: Instruction) -> InstructionResponse {
    InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .into_iter()
            .map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            })
            .collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    }
}

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let response = KeypairResponse {
        pubkey: keypair.pubkey().to_string(),
        secret: bs58::encode(keypair.secret().to_bytes()).into_string(),
    };
    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn create_token(
    Json(req): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    let mint_authority = match validate_pubkey(&req.mint_authority) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string())))),
    };
    
    let mint_pubkey = match validate_pubkey(&req.mint) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string())))),
    };

    let rent = solana_sdk::rent::Rent::default();
    let mint_len = spl_token::state::Mint::LEN;
    let mint_rent = rent.minimum_balance(mint_len);

    // Create account instruction
    let create_account_ix = system_instruction::create_account(
        &mint_authority,
        &mint_pubkey,
        mint_rent,
        mint_len as u64,
        &TOKEN_PROGRAM_ID,
    );

    // Initialize mint instruction
    let init_mint_ix = token_instruction::initialize_mint(
        &TOKEN_PROGRAM_ID,
        &mint_pubkey,
        &mint_authority,
        None,
        req.decimals,
    )
    .unwrap();

    // Return the initialize mint instruction as requested
    let response = instruction_to_response(init_mint_ix);
    Ok((StatusCode::OK, Json(ApiResponse::success(response))))
}

async fn mint_token(
    Json(req): Json<MintTokenRequest>,
) -> impl IntoResponse {
    let mint = match validate_pubkey(&req.mint) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };
    
    let destination = match validate_pubkey(&req.destination) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };
    
    let authority = match validate_pubkey(&req.authority) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };

    // Derive the associated token account for the destination
    let destination_ata = get_associated_token_address(&destination, &mint);

    let mint_to_ix = token_instruction::mint_to(
        &TOKEN_PROGRAM_ID,
        &mint,
        &destination_ata,
        &authority,
        &[],
        req.amount,
    )
    .unwrap();

    let response = instruction_to_response(mint_to_ix);
    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn sign_message(
    Json(req): Json<SignMessageRequest>,
) -> impl IntoResponse {
    if req.message.is_empty() || req.secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<SignMessageResponse>::error(ServerError::MissingFields.to_string())),
        );
    }

    let keypair = match validate_keypair(&req.secret) {
        Ok(kp) => kp,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<SignMessageResponse>::error(e.to_string()))),
    };

    let message_bytes = req.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    let response = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: req.message,
    };

    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn verify_message(
    Json(req): Json<VerifyMessageRequest>,
) -> impl IntoResponse {
    let pubkey = match validate_pubkey(&req.pubkey) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<VerifyMessageResponse>::error(e.to_string()))),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse>::error(ServerError::InvalidSignature.to_string())),
            )
        }
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<VerifyMessageResponse>::error(ServerError::InvalidSignature.to_string())),
            )
        }
    };

    let message_bytes = req.message.as_bytes();
    let valid = signature.verify(pubkey.as_ref(), message_bytes);

    let response = VerifyMessageResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };

    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn send_sol(
    Json(req): Json<SendSolRequest>,
) -> impl IntoResponse {
    // Validate inputs
    let from = match validate_pubkey(&req.from) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };
    
    let to = match validate_pubkey(&req.to) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };

    // Check valid inputs:
    // 1. From and to addresses must be different
    if from == to {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<InstructionResponse>::error(
                ServerError::InvalidAddresses("From and to addresses must be different".to_string()).to_string()
            )),
        );
    }

    // 2. Amount must be positive
    if req.lamports == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<InstructionResponse>::error(ServerError::InvalidAmount.to_string())),
        );
    }

    let transfer_ix = system_instruction::transfer(&from, &to, req.lamports);
    let response = instruction_to_response(transfer_ix);

    (StatusCode::OK, Json(ApiResponse::success(response)))
}

async fn send_token(
    Json(req): Json<SendTokenRequest>,
) -> impl IntoResponse {
    let destination = match validate_pubkey(&req.destination) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };
    
    let mint = match validate_pubkey(&req.mint) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };
    
    let owner = match validate_pubkey(&req.owner) {
        Ok(key) => key,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::<InstructionResponse>::error(e.to_string()))),
    };

    if req.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<InstructionResponse>::error(ServerError::InvalidAmount.to_string())),
        );
    }

    // Derive associated token accounts
    let source_ata = get_associated_token_address(&owner, &mint);
    let destination_ata = get_associated_token_address(&destination, &mint);

    // Create transfer instruction
    let transfer_ix = token_instruction::transfer(
        &TOKEN_PROGRAM_ID,
        &source_ata,
        &destination_ata,
        &owner,
        &[],
        req.amount,
    )
    .unwrap();

    // Note: The response format shows "isSigner" in camelCase in the example,
    // but I'm using snake_case as per Rust conventions. Let me know if you need camelCase.
    let response = instruction_to_response(transfer_ix);

    (StatusCode::OK, Json(ApiResponse::success(response)))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("Server running on http://0.0.0.0:3000");
    
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::new();
        let secret = bs58::encode(keypair.to_bytes()).into_string();
        let recovered = validate_keypair(&secret).unwrap();
        assert_eq!(keypair.pubkey(), recovered.pubkey());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = Keypair::new();
        let message = "Hello, Solana!";
        let signature = keypair.sign_message(message.as_bytes());
        
        assert!(signature.verify(keypair.pubkey().as_ref(), message.as_bytes()));
    }
}