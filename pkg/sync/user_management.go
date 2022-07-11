package sync

import (
	"context"
	"errors"
	"fmt"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"strconv"
	"strings"
)

type UserManagement interface {
	SyncUser(ctx context.Context, signedInUser *models.SignedInUser, email string, mappings string) (err error)
	getTeams(ctx context.Context, signedInUser *models.SignedInUser, orgID int64, teamName string) (teams []*models.TeamDTO, err error)
	addUserToOrg(ctx context.Context, userID int64, orgID int64, role string) error
	updateUserToOrg(ctx context.Context, userID int64, orgID int64, role string) error
	setActiveOrganization(ctx context.Context, userID int64, orgID int64) (err error)
	validateUsingOrg(ctx context.Context, userID int64, orgID int64) bool
	checkUserExistsInOrg(ctx context.Context, userID int64, orgID int64) (bool, error)
}

type Implementation struct {
	sqlStore               *sqlstore.SQLStore
	teamPermissionsService accesscontrol.TeamPermissionsService
	logger                 log.Logger
}

func ProvideUserManagementService(sqlStore *sqlstore.SQLStore, teamPermissionsService accesscontrol.TeamPermissionsService) *Implementation {
	s := &Implementation{
		sqlStore:               sqlStore,
		teamPermissionsService: teamPermissionsService,
		logger:                 log.New("sync.usermanagement"),
	}
	return s
}

// SyncUser Synchronise Grafana to organizations and roles provided by the mapping string
// Currently, this function assumes you want to assign the user to all teams inside the organization also
func (u *Implementation) SyncUser(ctx context.Context, signedInUser *models.SignedInUser, email string, mappings string) (err error) {
	u.logger.Info("Component Start", "sync_user", email)

	query := models.GetUserByEmailQuery{Email: email}
	if err = u.sqlStore.GetUserByEmail(ctx, &query); err != nil {
		u.logger.Error("failed to get user by email", "err", err)
		return err
	}

	user := query.Result

	if user == nil {
		u.logger.Error("User not found", "ctx", email)
		return errors.New("user not found")
	}

	u.logger.Info("User found", "ctx", user.Email)
	u.logger.Info("User org mappings", "ctx", mappings)

	if strings.Contains(mappings, ",") {
		roleMappingsPerOrg := strings.Split(mappings, ",")

		u.logger.Info("Multi mapping handler...")
		for _, roleMapping := range roleMappingsPerOrg {
			if u.handleRoleMappings(ctx, roleMapping, user, signedInUser) {
				continue
			}
		}
	} else {
		u.logger.Info("Single mapping handler...")
		u.handleRoleMappings(ctx, mappings, user, signedInUser)
	}

	return nil
}

func (u *Implementation) handleRoleMappings(ctx context.Context, roleMapping string, user *models.User, signedInUser *models.SignedInUser) (skip bool) {
	var err error
	if strings.Contains(roleMapping, ":") {
		split := strings.Split(roleMapping, ":")

		var orgName string
		var teamName string
		var roleName string

		// ORG:TEAM:ROLE
		if len(split) == 3 {
			orgName = split[0]
			teamName = split[1]
			roleName = split[2]
		} else {
			// ORG:ROLE
			orgName = split[0]
			roleName = split[1]
		}

		u.logger.Info("Checking user assignments for org:roleName", "ctx", split)

		if roleName == "GrafanaAdmin" {
			u.logger.Info("Adding Grafana admin permissions")

			if err = u.sqlStore.UpdateUserPermissions(user.Id, true); err != nil {
				u.logger.Error("failed to add grafana admin", "ctx", err)
			}
			return true
		}

		var org *models.Org
		if org, err = u.sqlStore.GetOrgByName(orgName); err != nil {
			if errors.Is(err, models.ErrOrgNotFound) {
				u.logger.Error("failed to find organisation", "ctx", orgName)
			}
			return true
		}

		u.logger.Info("Organisation found", "ctx", fmt.Sprintf("%d:%s", org.Id, org.Name))

		var userExistsInOrg bool
		userExistsInOrg, err = u.checkUserExistsInOrg(ctx, user.Id, org.Id)
		if err != nil {
			u.logger.Error("failed to check if user exists in org", "ctx", err)
			return true
		}

		if userExistsInOrg {
			u.logger.Info("user already exists in org, upserting role", "ctx", fmt.Sprintf("%s:%s:%s", user.Email, org.Name, roleName))
			if err = u.updateUserToOrg(ctx, user.Id, org.Id, roleName); err != nil {
				u.logger.Error("failed to update user in org", "ctx", err)
			}
		} else {
			u.logger.Info("adding user to org with roleName", "ctx", fmt.Sprintf("%s:%s:%s", user.Email, org.Name, roleName))

			if err = u.addUserToOrg(ctx, user.Id, org.Id, roleName); err != nil {
				u.logger.Error("failed to add user to org", "ctx", err)
				return true
			}
		}

		if err = u.setActiveOrganization(ctx, user.Id, org.Id); err != nil {
			u.logger.Error("failed to set active org for api user", "err", err)
		}

		if len(teamName) != 0 {
			u.logger.Info("searching for team name in orgID", "ctx", fmt.Sprintf("%s:%d", teamName, org.Id))
			var teams []*models.TeamDTO
			teams, err = u.getTeams(ctx, signedInUser, org.Id, teamName)
			if err != nil {
				u.logger.Error("failed to get teams", "err", err)
			}

			if len(teams) > 0 {
				for _, t := range teams {
					if t.Name == teamName {
						var userMemberOfTeam bool
						u.logger.Info("checking if user is a member of team", "ctx", fmt.Sprintf("%s:%s", user.Email, t.Name))
						if userMemberOfTeam, err = u.sqlStore.IsTeamMember(org.Id, t.Id, user.Id); err != nil {
							u.logger.Error("failed to check if user is a member of team", "err", err)
						}

						if userMemberOfTeam {
							u.logger.Info("user already member of team", "ctx", fmt.Sprintf("%s:%s", user.Email, t.Name))
							break
						}

						u.logger.Info("adding user as member to team", "ctx", fmt.Sprintf("%s:%s", user.Email, t.Name))
						err = addOrUpdateTeamMember(ctx, u.teamPermissionsService, user.Id, org.Id, t.Id, "Member")
						if err != nil {
							u.logger.Error("failed to add user to teams in org", "err", err)
						}
						// Break out once we find the desired team
						break
					}
				}
			} else {
				u.logger.Info("no teams found in org")
			}
		}
	}

	return false
}

var addOrUpdateTeamMember = func(ctx context.Context, resourcePermissionService accesscontrol.TeamPermissionsService, userID, orgID, teamID int64, permission string) error {
	teamIDString := strconv.FormatInt(teamID, 10)
	if _, err := resourcePermissionService.SetUserPermission(ctx, orgID, accesscontrol.User{ID: userID}, teamIDString, permission); err != nil {
		return fmt.Errorf("failed setting permissions for user %d in team %d: %w", userID, teamID, err)
	}
	return nil
}

func (u *Implementation) getTeams(ctx context.Context, signedInUser *models.SignedInUser, orgID int64, teamName string) (teams []*models.TeamDTO, err error) {
	signedInUser.OrgId = orgID

	wildCardTeams := make([]string, 1)
	wildCardTeams[0] = "teams:*"

	signedInUser.Permissions = map[int64]map[string][]string{
		orgID: {
			"teams:read": wildCardTeams,
		},
	}

	query := models.SearchTeamsQuery{
		OrgId:        orgID,
		Name:         teamName,
		UserIdFilter: 0,
		SignedInUser: signedInUser,
	}

	if err = u.sqlStore.SearchTeams(ctx, &query); err != nil {
		u.logger.Error("failed SearchTeams", "err", err)
		return nil, errors.New("failed to search Teams")
	}

	return query.Result.Teams, nil
}

func (u *Implementation) updateUserToOrg(ctx context.Context, userID int64, orgID int64, role string) error {
	cmd := models.UpdateOrgUserCommand{
		OrgId:  orgID,
		UserId: userID,
		Role:   models.RoleType(role),
	}

	if !cmd.Role.IsValid() {
		u.logger.Error("invalid role specified")
		return errors.New("invalid role specified")
	}

	if err := u.sqlStore.UpdateOrgUser(ctx, &cmd); err != nil {
		u.logger.Error("could not update user in organization", "err", err)
		return errors.New("could not update user in organization")
	}

	return nil
}

func (u *Implementation) addUserToOrg(ctx context.Context, userID int64, orgID int64, role string) error {
	cmd := models.AddOrgUserCommand{
		OrgId:  orgID,
		UserId: userID,
		Role:   models.RoleType(role),
	}

	if !cmd.Role.IsValid() {
		u.logger.Error("invalid role specified")
		return errors.New("invalid role specified")
	}

	if err := u.sqlStore.AddOrgUser(ctx, &cmd); err != nil {
		if errors.Is(err, models.ErrOrgUserAlreadyAdded) {
			u.logger.Error("user is already member of this organization", "err", err)
			return errors.New("user is already member of this organization")
		}
		u.logger.Error("could not add user to organization", "err", err)
		return errors.New("could not add user to organization")
	}

	return nil
}

func (u *Implementation) checkUserExistsInOrg(ctx context.Context, userID int64, orgID int64) (bool, error) {
	orgUsersQuery := &models.GetOrgUsersQuery{
		UserID:                   userID,
		OrgId:                    orgID,
		DontEnforceAccessControl: true,
	}

	if err := u.sqlStore.GetOrgUsers(ctx, orgUsersQuery); err != nil {
		u.logger.Error("failed to GetOrgUsers", "err", err)
		return false, err
	}

	return len(orgUsersQuery.Result) > 0, nil
}

func (u *Implementation) setActiveOrganization(ctx context.Context, userID int64, orgID int64) (err error) {
	if !u.validateUsingOrg(ctx, userID, orgID) {
		u.logger.Error("not a valid organisation")
		return errors.New("not a valid organisation")
	}

	cmd := models.SetUsingOrgCommand{UserId: userID, OrgId: orgID}

	if err = u.sqlStore.SetUsingOrg(context.TODO(), &cmd); err != nil {
		u.logger.Error("failed to set using org", "err", err)
		return err
	}

	return nil
}

func (u *Implementation) validateUsingOrg(ctx context.Context, userID int64, orgID int64) bool {
	query := models.GetUserOrgListQuery{UserId: userID}

	if err := u.sqlStore.GetUserOrgList(ctx, &query); err != nil {
		u.logger.Error("Error GetUserOrgList")
		return false
	}

	// validate that the org id in the list
	for _, other := range query.Result {
		u.logger.Info(fmt.Sprintf("org1 [%v] : org2 [%d]", other, orgID))
		if other.OrgId == orgID {
			u.logger.Info("validated")
			return true
		}
	}

	return false
}
