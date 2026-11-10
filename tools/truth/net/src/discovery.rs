//! Discovery vectors: `sui.Discovery` request/response bodies (BCS + snappy through the real
//! `BcsSnappyCodec`) holding signed node infos, signed exactly as sui-network does
//! (`keypair.sign(&bcs(node_info))`, discovery/mod.rs).
use anemo::rpc::codec::{Codec, Encoder};
use anyhow::Result;
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes, VerifyingKey};
use mysten_network::codec::anemo::BcsSnappyCodec;
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared_crypto::intent::IntentScope;
use std::collections::BTreeMap;
use std::io::Write;
use sui_types::digests::Digest;
use sui_types::message_envelope::{Envelope, Message};
use sui_types::multiaddr::Multiaddr;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessType {
    Public,
    Private,
    Trusted,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeInfo {
    pub peer_id: anemo::PeerId,
    pub addresses: Vec<Multiaddr>,
    pub timestamp_ms: u64,
    pub access_type: AccessType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NodeInfoDigest(Digest);
impl Message for NodeInfo {
    type DigestType = NodeInfoDigest;
    const SCOPE: IntentScope = IntentScope::DiscoveryPeers;
    fn digest(&self) -> Self::DigestType { unreachable!() }
}
pub type SignedNodeInfo = Envelope<NodeInfo, Ed25519Signature>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EndpointId {
    P2p(anemo::PeerId),
    Consensus(Ed25519PublicKey),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfoV2 {
    pub addresses: BTreeMap<EndpointId, Vec<Multiaddr>>,
    pub timestamp_ms: u64,
    pub access_type: AccessType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionedNodeInfo {
    V1(NodeInfo),
    V2(NodeInfoV2),
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VersionedNodeInfoDigest(Digest);
impl Message for VersionedNodeInfo {
    type DigestType = VersionedNodeInfoDigest;
    const SCOPE: IntentScope = IntentScope::DiscoveryPeers;
    fn digest(&self) -> Self::DigestType { unreachable!() }
}
pub type SignedVersionedNodeInfo = Envelope<VersionedNodeInfo, Ed25519Signature>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetKnownPeersResponseV2 {
    pub own_info: SignedNodeInfo,
    pub known_peers: Vec<SignedNodeInfo>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetKnownPeersRequestV3 {
    pub own_info: SignedVersionedNodeInfo,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetKnownPeersResponseV3 {
    pub own_info: SignedVersionedNodeInfo,
    pub known_peers: Vec<SignedVersionedNodeInfo>,
}

fn keypair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from(Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap())
}
fn pid(kp: &Ed25519KeyPair) -> anemo::PeerId {
    anemo::PeerId(kp.public().as_bytes().try_into().unwrap())
}
fn ma(s: &str) -> Multiaddr { s.parse().unwrap() }

fn sign_v1(info: NodeInfo, kp: &Ed25519KeyPair) -> SignedNodeInfo {
    let msg = bcs::to_bytes(&info).unwrap();
    SignedNodeInfo::new_from_data_and_sig(info, kp.sign(&msg))
}
fn sign_v(info: VersionedNodeInfo, kp: &Ed25519KeyPair) -> SignedVersionedNodeInfo {
    let msg = bcs::to_bytes(&info).unwrap();
    SignedVersionedNodeInfo::new_from_data_and_sig(info, kp.sign(&msg))
}

fn enc<T: Serialize + Send + 'static>(item: T) -> (Vec<u8>, Vec<u8>) {
    let b = bcs::to_bytes(&item).unwrap();
    let mut c = BcsSnappyCodec::<T, ()>::default();
    (b, c.encoder().encode(item).unwrap().to_vec())
}

pub fn run(out: &str) -> Result<()> {
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    let mut n = 0;
    let mut emit = |v: serde_json::Value| -> Result<()> { writeln!(f, "{v}")?; n += 1; Ok(()) };
    let addrs = [
        vec![ma("/ip4/203.0.113.8/udp/8084")],
        vec![ma("/dns/validator-1.example.net/udp/8084"), ma("/ip4/10.0.0.7/udp/8084")],
        vec![ma("/ip6/2001:db8::1/udp/8084")],
        vec![],
    ];
    // V1 responses
    for variant in 0..4usize {
        let own_kp = keypair(1);
        let own = sign_v1(NodeInfo { peer_id: pid(&own_kp), addresses: addrs[0].clone(), timestamp_ms: 1_700_000_000_000, access_type: AccessType::Public }, &own_kp);
        let mut peers = Vec::new();
        for k in 0..variant * 3 {
            let kp = keypair(10 + k as u8);
            peers.push(sign_v1(NodeInfo { peer_id: pid(&kp), addresses: addrs[k % 4].clone(), timestamp_ms: 1_700_000_000_000 + k as u64, access_type: [AccessType::Public, AccessType::Private, AccessType::Trusted][k % 3] }, &kp));
        }
        let desc: Vec<_> = peers.iter().chain(std::iter::once(&own)).map(|p| json!({
            "peer_id": hex::encode(p.data().peer_id.0), "addresses": p.data().addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            "timestamp_ms": p.data().timestamp_ms, "access": format!("{:?}", p.data().access_type), "signature_valid": true,
            "sig": hex::encode(p.auth_sig().as_bytes()),
        })).collect();
        let (b, s) = enc(GetKnownPeersResponseV2 { own_info: own, known_peers: peers });
        emit(json!({"id":format!("v2/{variant}"),"kind":"GetKnownPeersResponseV2","bcs_hex":hex::encode(&b),"snappy_hex":hex::encode(&s),"peers":desc}))?;
    }
    // a response with one corrupted signature (signature_valid must come out false)
    {
        let kp = keypair(1);
        let good = sign_v1(NodeInfo { peer_id: pid(&kp), addresses: addrs[0].clone(), timestamp_ms: 5, access_type: AccessType::Public }, &kp);
        let other = keypair(2);
        let msg = bcs::to_bytes(good.data()).unwrap();
        let bad = SignedNodeInfo::new_from_data_and_sig(good.data().clone(), other.sign(&msg)); // signed by the wrong key
        let (b, s) = enc(GetKnownPeersResponseV2 { own_info: good.clone(), known_peers: vec![bad.clone()] });
        let d = |p: &SignedNodeInfo, valid: bool| json!({"peer_id": hex::encode(p.data().peer_id.0), "addresses": p.data().addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(), "timestamp_ms": p.data().timestamp_ms, "access": format!("{:?}", p.data().access_type), "signature_valid": valid, "sig": hex::encode(p.auth_sig().as_bytes())});
        emit(json!({"id":"v2/badsig","kind":"GetKnownPeersResponseV2","bcs_hex":hex::encode(&b),"snappy_hex":hex::encode(&s),"peers":[d(&bad,false), d(&good,true)]}))?;
    }
    // V3: versioned infos (V1 inside, and V2 with endpoint map)
    for variant in 0..3usize {
        let own_kp = keypair(1);
        let own = sign_v(VersionedNodeInfo::V1(NodeInfo { peer_id: pid(&own_kp), addresses: addrs[0].clone(), timestamp_ms: 77, access_type: AccessType::Public }), &own_kp);
        let mut peers = Vec::new();
        let mut desc = Vec::new();
        for k in 0..variant * 2 + 1 {
            let kp = keypair(30 + k as u8);
            let mut map = BTreeMap::new();
            map.insert(EndpointId::P2p(pid(&kp)), addrs[k % 3].clone());
            if k % 2 == 1 { map.insert(EndpointId::Consensus(kp.public().clone()), vec![ma("/ip4/1.2.3.4/udp/8080")]); }
            let info = VersionedNodeInfo::V2(NodeInfoV2 { addresses: map, timestamp_ms: 900 + k as u64, access_type: AccessType::Public });
            let s = sign_v(info, &kp);
            desc.push(json!({"peer_id": hex::encode(pid(&kp).0), "version": 2, "p2p_addresses": addrs[k % 3].iter().map(|a| a.to_string()).collect::<Vec<_>>(), "timestamp_ms": 900 + k as u64, "signature_valid": true, "sig": hex::encode(s.auth_sig().as_bytes())}));
            peers.push(s);
        }
        desc.push(json!({"peer_id": hex::encode(pid(&own_kp).0), "version": 1, "p2p_addresses": addrs[0].iter().map(|a| a.to_string()).collect::<Vec<_>>(), "timestamp_ms": 77, "signature_valid": true, "sig": hex::encode(own.auth_sig().as_bytes())}));
        let (b, s) = enc(GetKnownPeersResponseV3 { own_info: own.clone(), known_peers: peers });
        emit(json!({"id":format!("v3/{variant}"),"kind":"GetKnownPeersResponseV3","bcs_hex":hex::encode(&b),"snappy_hex":hex::encode(&s),"peers":desc}))?;
        let (b, s) = enc(GetKnownPeersRequestV3 { own_info: own });
        emit(json!({"id":format!("v3req/{variant}"),"kind":"GetKnownPeersRequestV3","bcs_hex":hex::encode(&b),"snappy_hex":hex::encode(&s)}))?;
    }
    eprintln!("discovery: {n} vectors");
    Ok(())
}
