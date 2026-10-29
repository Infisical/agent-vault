//go:build darwin && cgo

package macosprovider

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef av_cf_string(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static OSStatus av_keychain_copy(const char *service, const char *account, const char *group,
		Boolean allow_ui, uint8_t **output, size_t *output_length) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!query) return errSecAllocate;
	CFStringRef service_value = av_cf_string(service);
	CFStringRef account_value = av_cf_string(account);
	CFStringRef group_value = group && group[0] ? av_cf_string(group) : NULL;
	if (!service_value || !account_value || ((group && group[0]) && !group_value)) {
		if (service_value) CFRelease(service_value);
		if (account_value) CFRelease(account_value);
		if (group_value) CFRelease(group_value);
		CFRelease(query);
		return errSecAllocate;
	}
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service_value);
	CFDictionarySetValue(query, kSecAttrAccount, account_value);
	if (group_value) CFDictionarySetValue(query, kSecAttrAccessGroup, group_value);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecUseAuthenticationUI,
		allow_ui ? kSecUseAuthenticationUIAllow : kSecUseAuthenticationUIFail);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(service_value);
	CFRelease(account_value);
	if (group_value) CFRelease(group_value);
	CFRelease(query);
	if (status != errSecSuccess) {
		if (result) CFRelease(result);
		return status;
	}
	if (!result || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result) CFRelease(result);
		return errSecDecode;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex length = CFDataGetLength(data);
	if (length <= 0 || length > 65536) {
		CFRelease(result);
		return errSecDataTooLarge;
	}
	uint8_t *copy = (uint8_t *)malloc((size_t)length);
	if (!copy) {
		CFRelease(result);
		return errSecAllocate;
	}
	memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
	CFRelease(result);
	*output = copy;
	*output_length = (size_t)length;
	return errSecSuccess;
}

static void av_keychain_free(uint8_t *value, size_t length) {
	if (value) {
		volatile uint8_t *cursor = value;
		for (size_t i = 0; i < length; i++) cursor[i] = 0;
		free(value);
	}
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

func (platformKeychain) CopyMatching(ctx context.Context, item KeychainItem) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keychain request cancelled")
	}
	if err := validateKeychainItem(item); err != nil {
		return nil, err
	}
	service := C.CString(item.Service)
	account := C.CString(item.Account)
	group := C.CString(item.AccessGroup)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	defer C.free(unsafe.Pointer(group))
	var output *C.uint8_t
	var length C.size_t
	allowUI := C.Boolean(0)
	if item.AllowUserInteraction {
		allowUI = 1
	}
	status := C.av_keychain_copy(service, account, group, allowUI, &output, &length)
	if status != 0 || output == nil || length == 0 || length > C.size_t(maxCommandOutput) {
		if output != nil {
			C.av_keychain_free(output, length)
		}
		return nil, fmt.Errorf("keychain item unavailable")
	}
	defer C.av_keychain_free(output, length)
	return C.GoBytes(unsafe.Pointer(output), C.int(length)), nil
}
