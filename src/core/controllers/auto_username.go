package controllers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/common/utils/log"
	"github.com/pkg/errors"
)

// onboardAutoUser handles the request to onboard an user authenticated via OIDC provider
func (oc *OIDCController) onboardAutoUser() {
	userInfoStr, ok := oc.GetSession(userInfoKey).(string)
	if !ok {
		oc.SendBadRequestError(errors.New("Failed to get OIDC user info from session"))
		return
	}
	log.Debugf("User info string: %s\n", userInfoStr)
	tb, ok := oc.GetSession(tokenKey).([]byte)
	if !ok {
		oc.SendBadRequestError(errors.New("Failed to get OIDC token from session"))
		return
	}
	s, t, err := secretAndToken(tb)
	if err != nil {
		oc.SendInternalServerError(err)
		return
	}
	d := &oidcUserData{}
	err = json.Unmarshal([]byte(userInfoStr), &d)
	if err != nil {
		oc.SendInternalServerError(err)
		return
	}
	oidcUser := models.OIDCUser{
		SubIss: d.Subject + d.Issuer,
		Secret: s,
		Token:  t,
	}

	username := d.Email
	if utils.IsIllegalLength(username, 1, 255) {
		oc.SendBadRequestError(errors.New("username with illegal length"))
		return
	}
	if utils.IsContainIllegalChar(username, []string{",", "~", "#", "$", "%"}) {
		oc.SendBadRequestError(errors.New("username contains illegal characters"))
		return
	}

	user := models.User{
		Username:     username,
		Realname:     d.Username,
		Email:        d.Email,
		OIDCUserMeta: &oidcUser,
		Comment:      oidcUserComment,
	}

	if err := dao.OnBoardOIDCUser(&user); err != nil {
		if strings.Contains(err.Error(), dao.ErrDupUser.Error()) {
			oc.RenderError(http.StatusConflict, "Conflict in username, the user with same username has been onboarded.")
			return
		}
		oc.SendInternalServerError(err)
		oc.DelSession(userInfoKey)
		return
	}

	user.OIDCUserMeta = nil
	oc.SetSession(userKey, user)
	oc.DelSession(userInfoKey)
	oc.Controller.Redirect("/", http.StatusFound)
}