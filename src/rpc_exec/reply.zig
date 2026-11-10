//! One gRPC reply of TransactionExecutionService: the response message, or the status tonic
//! sends for sui-rpc-api's `RpcError` (code, message, `grpc-status-details-bin`).
pub const RpcError = struct {
    /// gRPC status code (3 INVALID_ARGUMENT, 12 UNIMPLEMENTED, 13 INTERNAL, ...).
    code: u8,
    message: []const u8,
    /// `grpc-status-details-bin` (a `google.rpc.Status`); empty when tonic sends none.
    details: []const u8 = &.{},
};

pub const Reply = union(enum) {
    /// Encoded response message (SimulateTransactionResponse / ExecuteTransactionResponse).
    ok: []const u8,
    err: RpcError,
};
