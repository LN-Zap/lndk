use crate::lnd::{get_lnd_client, get_network, Creds, LndCfg};
use crate::lndk_offers::get_destination;
use crate::{lndkrpc, OfferError, OfferHandler, PayOfferParams};
use bitcoin::secp256k1::PublicKey;
use lightning::offers::offer::Offer;
use lndkrpc::offers_server::Offers;
use lndkrpc::{PayOfferRequest, PayOfferResponse, GetInvoiceResponse, Bolt12InvoiceData};
use lightning::offers::invoice::BlindedPayInfo;
use lightning::blinded_path::BlindedPath;
use lightning::util::ser::Writeable;
use std::str::FromStr;
use std::sync::Arc;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};
use tonic_lnd::lnrpc::GetInfoRequest;

pub struct LNDKServer {
    offer_handler: Arc<OfferHandler>,
    node_id: PublicKey,
    // The LND tls cert we need to establish a connection with LND.
    lnd_cert: String,
    address: String,
}

impl LNDKServer {
    pub async fn new(
        offer_handler: Arc<OfferHandler>,
        node_id: &str,
        lnd_cert: String,
        address: String,
    ) -> Self {
        Self {
            offer_handler,
            node_id: PublicKey::from_str(node_id).unwrap(),
            lnd_cert,
            address,
        }
    }
}

#[tonic::async_trait]
impl Offers for LNDKServer {
    async fn get_invoice(
        &self,
        request: Request<PayOfferRequest>,
    ) -> Result<Response<GetInvoiceResponse>, Status> {
        let metadata = request.metadata();
        let macaroon = check_auth_metadata(metadata)?;
        let creds = Creds::String {
            cert: self.lnd_cert.clone(),
            macaroon,
        };
        let lnd_cfg = LndCfg::new(self.address.clone(), creds);
        let mut client = get_lnd_client(lnd_cfg)
            .map_err(|e| Status::unavailable(format!("Couldn't connect to lnd: {e}")))?;

        let inner_request = request.get_ref();
        let offer = Offer::from_str(&inner_request.offer).map_err(|e| {
            Status::invalid_argument(format!(
                "The provided offer was invalid. Please provide a valid offer in bech32 format,
                i.e. starting with 'lno'. Error: {e:?}"
            ))
        })?;

        let destination = get_destination(&offer).await;
        let reply_path = match self
            .offer_handler
            .create_reply_path(client.clone(), self.node_id, offer.signing_pubkey())
            .await
        {
            Ok(reply_path) => reply_path,
            Err(e) => return Err(Status::internal(format!("Internal error: {e}"))),
        };

        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();
        let network = get_network(info)
            .await
            .map_err(|e| Status::internal(format!("{e:?}")))?;

        let cfg = PayOfferParams {
            offer,
            amount: inner_request.amount,
            network,
            client,
            destination,
            reply_path: Some(reply_path),
        };

        let invoice = match self.offer_handler.get_invoice(cfg).await {
            Ok(invoice) => {
                log::info!("GetInvoice succeeded.");
                log::debug!("Invoice: {:?}", invoice);
                invoice
            }
            Err(e) => match e {
                OfferError::AlreadyProcessing => {
                    return Err(Status::already_exists(format!("{e}")))
                }
                OfferError::InvalidAmount(e) => {
                    return Err(Status::invalid_argument(e.to_string()))
                }
                OfferError::InvalidCurrency => {
                    return Err(Status::invalid_argument(format!("{e}")))
                }
                _ => return Err(Status::internal(format!("Internal error: {e}"))),
            },
        };

        let amount_msats = invoice.amount_msats();

        let payment_hash_bytes = invoice.payment_hash().encode();
        let payment_hash = lndkrpc::PaymentHash {
            hash: payment_hash_bytes
        };

        let signing_pubkey_bytes = invoice.signing_pubkey().encode();
        let signing_pubkey = lndkrpc::PublicKey {
            key: signing_pubkey_bytes
        };

        // Conversion function for BlindedPayInfo
        fn convert_blinded_pay_info(native_info: &BlindedPayInfo) -> lndkrpc::BlindedPayInfo {
            lndkrpc::BlindedPayInfo {
                fee_base_msat: native_info.fee_base_msat,
                fee_proportional_millionths: native_info.fee_proportional_millionths,
                cltv_expiry_delta: native_info.cltv_expiry_delta as u32,
                htlc_minimum_msat: native_info.htlc_minimum_msat,
                htlc_maximum_msat: native_info.htlc_maximum_msat,
                features: native_info.features.encode().iter().map(|&b| b as i32).collect()
            }
        }

        fn convert_public_key(native_pub_key: PublicKey) -> lndkrpc::PublicKey {
            let pub_key_bytes = native_pub_key.encode(); // Assuming `encode` returns Vec<u8>
            lndkrpc::PublicKey {
                key: pub_key_bytes,
            }
        }

        fn convert_bytes_to_u32_vec(bytes: Vec<u8>) -> Vec<u32> {
            bytes.chunks(4).filter_map(|chunk| {
                if chunk.len() == 4 {
                    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                } else {
                    None // Ignore incomplete chunks
                }
            }).collect()
        }

        // Conversion function for BlindedPath
        fn convert_blinded_path(native_info: &BlindedPath) -> lndkrpc::BlindedPath {

            let introduction_node_id_bytes = native_info.introduction_node_id.encode();
            let introduction_node_id = lndkrpc::PublicKey {
                key: introduction_node_id_bytes
            };


            let blinding_point_bytes = native_info.blinding_point.encode();
            let blinding_point = lndkrpc::PublicKey {
                key: blinding_point_bytes
            };

            lndkrpc::BlindedPath {
                introduction_node_id: Some(introduction_node_id),
                blinding_point: Some(blinding_point),
                blinded_hops: native_info.blinded_hops.iter().map(|hop| lndkrpc::BlindedHop {
                    blinded_node_id: Some(convert_public_key(hop.blinded_node_id)),
                    encrypted_payload: convert_bytes_to_u32_vec(hop.encrypted_payload.clone()),
                }).collect(),
            }
        }

        let payment_paths: &[(lightning::offers::invoice::BlindedPayInfo, lightning::blinded_path::BlindedPath)] = invoice.payment_paths();

        let payment_paths_vec: Vec<lndkrpc::PaymentPaths> = payment_paths.iter().map(|(blinded_pay_info, blinded_path)| {
            lndkrpc::PaymentPaths {
                blinded_pay_info: Some(convert_blinded_pay_info(blinded_pay_info)),
                blinded_path: Some(convert_blinded_path(blinded_path))
            }
        }).collect();

        let reply = GetInvoiceResponse {
            invoice: Some(Bolt12InvoiceData {
                amount: amount_msats,
                description: invoice.description().to_string(),
                payment_hash: Some(payment_hash),
                relative_expiry: invoice.relative_expiry().as_secs(),
                signing_pubkey: Some(signing_pubkey),
                payment_paths: payment_paths_vec,
            }),
        };

        Ok(Response::new(reply))
    }

    async fn pay_offer(
        &self,
        request: Request<PayOfferRequest>,
    ) -> Result<Response<PayOfferResponse>, Status> {
        log::info!("Received a request: {:?}", request);

        let metadata = request.metadata();
        let macaroon = check_auth_metadata(metadata)?;
        let creds = Creds::String {
            cert: self.lnd_cert.clone(),
            macaroon,
        };
        let lnd_cfg = LndCfg::new(self.address.clone(), creds);
        let mut client = get_lnd_client(lnd_cfg)
            .map_err(|e| Status::unavailable(format!("Couldn't connect to lnd: {e}")))?;

        let inner_request = request.get_ref();
        let offer = Offer::from_str(&inner_request.offer).map_err(|e| {
            Status::invalid_argument(format!(
                "The provided offer was invalid. Please provide a valid offer in bech32 format,
                i.e. starting with 'lno'. Error: {e:?}"
            ))
        })?;

        let destination = get_destination(&offer).await;
        let reply_path = match self
            .offer_handler
            .create_reply_path(client.clone(), self.node_id, offer.signing_pubkey())
            .await
        {
            Ok(reply_path) => reply_path,
            Err(e) => return Err(Status::internal(format!("Internal error: {e}"))),
        };

        let info = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .expect("failed to get info")
            .into_inner();
        let network = get_network(info)
            .await
            .map_err(|e| Status::internal(format!("{e:?}")))?;

        let cfg = PayOfferParams {
            offer,
            amount: inner_request.amount,
            network,
            client,
            destination,
            reply_path: Some(reply_path),
        };

        let payment = match self.offer_handler.pay_offer(cfg).await {
            Ok(payment) => {
                log::info!("Payment succeeded.");
                payment
            }
            Err(e) => match e {
                OfferError::AlreadyProcessing => {
                    return Err(Status::already_exists(format!("{e}")))
                }
                OfferError::InvalidAmount(e) => {
                    return Err(Status::invalid_argument(e.to_string()))
                }
                OfferError::InvalidCurrency => {
                    return Err(Status::invalid_argument(format!("{e}")))
                }
                _ => return Err(Status::internal(format!("Internal error: {e}"))),
            },
        };

        let reply = PayOfferResponse {
            payment_preimage: payment.payment_preimage,
        };

        Ok(Response::new(reply))
    }
}

// We need to check that the client passes in a tls cert pem string, hexadecimal macaroon,
// and address, so they can connect to LND.
fn check_auth_metadata(metadata: &MetadataMap) -> Result<String, Status> {
    let macaroon = match metadata.get("macaroon") {
        Some(macaroon_hex) => macaroon_hex
            .to_str()
            .map_err(|e| {
                Status::invalid_argument(format!("Invalid macaroon string provided: {e}"))
            })?
            .to_string(),
        _ => {
            return Err(Status::unauthenticated(
                "No LND macaroon provided: Make sure to provide macaroon in request metadata",
            ))
        }
    };

    Ok(macaroon)
}
