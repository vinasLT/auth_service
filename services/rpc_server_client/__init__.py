import os
import sys

# Ensure generated gRPC modules under services/rpc_server_client/gen/python are importable.
_GRPC_GEN_PATH = os.path.join(os.path.dirname(__file__), "gen", "python")
if _GRPC_GEN_PATH not in sys.path:
    sys.path.insert(0, _GRPC_GEN_PATH)
