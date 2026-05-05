// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package ldap

import (
	"context"
	"strings"

	auth_model "code.gitea.io/gitea/models/auth"
	user_model "code.gitea.io/gitea/models/user"
)

// SourceProvidesTOTPSecret returns true when the login source is LDAP and has a TOTP secret attribute configured.
func SourceProvidesTOTPSecret(source *auth_model.Source) bool {
	if source == nil {
		return false
	}
	cfg, ok := source.Cfg.(*Source)
	if !ok {
		return false
	}
	return cfg.ProvidesTOTPSecret()
}

// UserHasLDAPManagedTOTP returns true if the user authenticates through an LDAP source with a configured TOTP secret attribute.
func UserHasLDAPManagedTOTP(ctx context.Context, user *user_model.User) (bool, error) {
	if user == nil {
		return false, nil
	}
	source, err := auth_model.GetSourceByID(ctx, user.LoginSource)
	if err != nil {
		return false, err
	}
	return SourceProvidesTOTPSecret(source), nil
}

func synchronizeTOTP(ctx context.Context, user *user_model.User, totpSecret string) error {
	totpSecret = strings.TrimSpace(totpSecret)
	twofa, err := auth_model.GetTwoFactorByUID(ctx, user.ID)
	if err != nil && !auth_model.IsErrTwoFactorNotEnrolled(err) {
		return err
	}

	if totpSecret == "" {
		if err == nil {
			return auth_model.DeleteTwoFactorByID(ctx, twofa.ID, user.ID)
		}
		return nil
	}

	if err == nil {
		if setErr := twofa.SetSecret(totpSecret); setErr != nil {
			return setErr
		}
		twofa.IsEnrolledByLDAP = true
		twofa.LastUsedPasscode = ""
		return auth_model.UpdateTwoFactor(ctx, twofa)
	}

	twofa = &auth_model.TwoFactor{
		UID:              user.ID,
		IsEnrolledByLDAP: true,
	}
	if err := twofa.SetSecret(totpSecret); err != nil {
		return err
	}
	return auth_model.NewTwoFactor(ctx, twofa)
}
