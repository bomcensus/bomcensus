// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package winacl

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS.
const fileAllAccess = 0x1F01FF

// ProtectDir makes the current account the owner of dir and replaces its
// DACL with full control for LocalSystem, Administrators, the current
// account and the extra SIDs, inherited by files and subdirectories.
// Existing children that inherit their DACL are updated by the system. It
// fails when the DACL cannot be set, or when the owner cannot be changed
// and is not one of the trusted principals.
func ProtectDir(dir string, extra ...*windows.SID) error {
	return protect(dir, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, extra)
}

// ProtectFile does what ProtectDir does for a single file, without
// inheritance.
func ProtectFile(path string, extra ...*windows.SID) error {
	return protect(path, windows.NO_INHERITANCE, extra)
}

// ServiceSID returns the SID of the virtual account NT SERVICE\<name>. It
// is derived from the name (S-1-5-80 followed by the SHA-1 of the upper-case
// UTF-16LE name as five 32-bit values), so it exists before the service is
// installed.
func ServiceSID(name string) (*windows.SID, error) {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b)
	s := "S-1-5-80"
	for i := 0; i < 5; i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return windows.StringToSid(s)
}

// Trusted returns the SIDs that get full control: LocalSystem,
// Administrators and the user of the process token (for a service with a
// virtual account, NT SERVICE\<name>).
func Trusted() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("token user: %w", err)
	}
	self, err := u.User.Sid.Copy()
	if err != nil {
		return nil, err
	}
	return []*windows.SID{system, admins, self}, nil
}

func protect(path string, inheritance uint32, extra []*windows.SID) error {
	sids, err := Trusted()
	if err != nil {
		return err
	}
	self := sids[len(sids)-1]
	for _, sid := range extra {
		if sid != nil && !contains(sids, sid) {
			sids = append(sids, sid)
		}
	}
	entries := make([]windows.EXPLICIT_ACCESS, len(sids))
	for i, sid := range sids {
		entries[i] = windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build ACL: %w", err)
	}

	// Taking ownership needs WRITE_OWNER, which the current owner or an
	// administrator has. When it fails, an owner that is already trusted is
	// fine; any other owner could rewrite the DACL later.
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, self, nil, nil, nil); err != nil {
		owner, oerr := ownerOf(path)
		if oerr != nil {
			return fmt.Errorf("set owner of %s: %w", path, err)
		}
		if !contains(sids, owner) {
			return fmt.Errorf("set owner of %s: %w (owned by %s)", path, err, owner)
		}
	}
	si := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, si, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set DACL of %s: %w", path, err)
	}
	return nil
}

func ownerOf(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func contains(list []*windows.SID, sid *windows.SID) bool {
	for _, s := range list {
		if s.Equals(sid) {
			return true
		}
	}
	return false
}

// IsProtected reports whether path has what ProtectDir would give it: an
// owner among the trusted and extra SIDs, and a protected DACL of allow
// entries for those SIDs only, with full control inherited by files and
// subdirectories for LocalSystem, Administrators, every extra SID and the
// current account. The current account needs no entry of its own when it
// is a member of Administrators. Callers use it to leave a directory alone
// that is already set up (by an earlier call or by the installer).
func IsProtected(path string, extra ...*windows.SID) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	trusted, err := Trusted()
	if err != nil {
		return false, err
	}
	system, admins, self := trusted[0], trusted[1], trusted[2]
	allowed := append(append([]*windows.SID(nil), trusted...), extra...)
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil || !contains(allowed, owner) {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return false, nil
	}
	const inherit = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	var full []*windows.SID
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !contains(allowed, sid) {
			return false, nil
		}
		if ace.Mask&fileAllAccess == fileAllAccess && ace.Header.AceFlags&inherit == inherit {
			full = append(full, sid)
		}
	}
	required := append([]*windows.SID{system, admins}, extra...)
	if !contains(full, self) {
		// Token 0 is the token of the calling thread or process.
		if isAdmin, err := windows.Token(0).IsMember(admins); err != nil || !isAdmin {
			required = append(required, self)
		}
	}
	for _, sid := range required {
		if sid != nil && !contains(full, sid) {
			return false, nil
		}
	}
	return true, nil
}

// Check reports an error unless path has a protected DACL that grants
// access to the trusted SIDs and the extra ones only. Tests and
// diagnostics use it.
func Check(path string, extra ...*windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return err
	}
	if ctl&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s: DACL is not protected", path)
	}
	return grantsOnlyTrusted(path, sd, extra)
}

// CheckGrants is Check without the protected flag, for the children of a
// protected directory: they inherit its entries but are not protected
// themselves.
func CheckGrants(path string, extra ...*windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return grantsOnlyTrusted(path, sd, extra)
}

// grantsOnlyTrusted reports an error unless every entry of the DACL of sd
// names a trusted or an extra SID.
func grantsOnlyTrusted(path string, sd *windows.SECURITY_DESCRIPTOR, extra []*windows.SID) error {
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("%s: no DACL", path)
	}
	sids, err := Trusted()
	if err != nil {
		return err
	}
	sids = append(sids, extra...)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !contains(sids, sid) {
			return fmt.Errorf("%s: access granted to %s", path, sid)
		}
	}
	return nil
}
