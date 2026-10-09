from fastapi import APIRouter

from app.devices.discovery import discover_physical_devices_detailed
from app.devices.images import list_images
from app.sanitization.policy import list_methods
from app.schemas import DevicesResponse, ImageTargetOut, MethodOut, PhysicalDeviceOut

router = APIRouter(prefix="/api", tags=["devices"])


@router.get("/devices", response_model=DevicesResponse)
def get_devices() -> DevicesResponse:
    try:
        found, warnings = discover_physical_devices_detailed()
        physical = [PhysicalDeviceOut(**d.to_dict()) for d in found]
    except Exception as exc:  # noqa: BLE001
        physical = []
        warnings = [f"Physical device discovery crashed unexpectedly: {exc}"]

    images = [ImageTargetOut(**img) for img in list_images()]
    return DevicesResponse(physical_devices=physical, image_targets=images, discovery_warnings=warnings)


@router.get("/methods", response_model=list[MethodOut])
def get_methods() -> list[MethodOut]:
    return [MethodOut(**m) for m in list_methods()]
