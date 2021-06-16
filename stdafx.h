#pragma once
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <IndustryStandard/PeImage.h>
#include <Guid/GlobalVariable.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmSwDispatch2.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Protocol/SmmUsbDispatch2.h>
#include "util.h"


