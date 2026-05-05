// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v1_27

import "xorm.io/xorm"

func AddIsEnrolledByLDAPToTwoFactor(x *xorm.Engine) error {
	type TwoFactor struct {
		IsEnrolledByLDAP bool `xorm:"NOT NULL DEFAULT false"`
	}
	return x.Sync(new(TwoFactor))
}
