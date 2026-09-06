import os
import json
import time
from typing import Optional, Dict, Any, List
import httpx
from src.config import config

class RunPodOrchestrator:
    """Orchestrator for managing RunPod GPU compute instances for heavy vector operations."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("RUNPOD_API_KEY", "")
        self.base_url = "https://api.runpod.io/graphql"
        self.rest_url = "https://rest.runpod.io/v2"

    def get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def check_cuda_availability(self) -> Dict[str, Any]:
        """Check if local environment or active container has PyTorch CUDA acceleration available."""
        try:
            import torch
            available = torch.cuda.is_available()
            device_name = torch.cuda.get_device_name(0) if available else "CPU (Fallback)"
            device_count = torch.cuda.device_count() if available else 0
            return {
                "cuda_available": available,
                "device_name": device_name,
                "device_count": device_count,
                "torch_version": torch.__version__
            }
        except ImportError:
            return {
                "cuda_available": False,
                "device_name": "CPU (PyTorch not found)",
                "device_count": 0,
                "torch_version": "N/A"
            }

    def create_gpu_pod_spec(
        self, 
        name: str = "cti-rag-poison-benchmark-gpu",
        gpu_type: str = "NVIDIA GeForce RTX 4090",
        image_name: str = "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04"
    ) -> Dict[str, Any]:
        """Generate specification for creating a RunPod GPU pod."""
        return {
            "name": name,
            "imageName": image_name,
            "gpuTypeIds": [gpu_type],
            "gpuCount": 1,
            "cloudType": "COMMUNITY",
            "containerDiskInGb": 40,
            "volumeInGb": 20,
            "env": {
                "OPENROUTER_API_KEY": config.OPENROUTER_API_KEY,
                "DENSE_MODEL_NAME": config.DENSE_MODEL_NAME,
                "RERANKER_MODEL_NAME": config.RERANKER_MODEL_NAME
            }
        }
