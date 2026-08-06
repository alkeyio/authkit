package codegen

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alkeyio/authkit/integrations/sql"
	codegen "github.com/alkeyio/authkit/mocks/rfc6749/code_generator"
	"github.com/alkeyio/authkit/requests"
	"github.com/alkeyio/authkit/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGenerator_New(t *testing.T) {
	g := New(NewOptions().SetExpiresIn(time.Hour * 24).SetCodeLength(128))
	assert.Equal(t, time.Hour*24, g.expiresIn)
	assert.Equal(t, 128, g.codeLength)

	g = New()
	assert.Equal(t, DefaultExpiresIn, g.expiresIn)
	assert.Equal(t, DefaultCodeLength, g.codeLength)
}

func TestGenerator_Generate(t *testing.T) {
	newReq := func() *requests.AuthorizationRequest {
		return &requests.AuthorizationRequest{
			GrantType:    types.GrantTypeAuthorizationCode,
			RedirectURI:  "http://example.com",
			ResponseType: types.ResponseTypeCode,
			Scopes:       types.NewScopes([]string{"profile", "openid"}),
			State:        uuid.NewString(),
			Client:       &sql.Client{ClientID: uuid.NewString()},
			User:         &sql.User{UserID: uuid.NewString()},
		}
	}

	t.Run("success_with_extra_data_generator", func(t *testing.T) {
		r := newReq()
		mockAuthCode := &sql.AuthorizationCode{}
		extraDataGen := codegen.NewMockExtraDataGenerator(t)
		extraData := map[string]interface{}{"session_id": uuid.NewString()}
		extraDataGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("*requests.AuthorizationRequest")).Return(extraData, nil).Once()

		g := New(NewOptions().SetExtraDataGenerator(extraDataGen.Execute))
		err := g.Generate(context.Background(), mockAuthCode, r)
		assert.NoError(t, err)
		assert.Equal(t, DefaultCodeLength, len(mockAuthCode.GetCode()))
		assert.Equal(t, r.Client.GetClientID(), mockAuthCode.GetClientID())
		assert.Equal(t, r.User.GetUserID(), mockAuthCode.GetUserID())
		assert.Equal(t, r.RedirectURI, mockAuthCode.GetRedirectURI())
		assert.Equal(t, r.ResponseType, mockAuthCode.GetResponseType())
		assert.Equal(t, r.Scopes, mockAuthCode.GetScopes())
		assert.Equal(t, r.State, mockAuthCode.GetState())
		assert.False(t, mockAuthCode.GetAuthTime().IsZero())
		assert.Equal(t, DefaultExpiresIn, mockAuthCode.GetExpiresIn())
		assert.Equal(t, extraData, mockAuthCode.GetExtraData())
	})

	t.Run("success_without_extra_data_generator", func(t *testing.T) {
		r := newReq()
		mockAuthCode := &sql.AuthorizationCode{}

		g := New(NewOptions())
		err := g.Generate(context.Background(), mockAuthCode, r)
		assert.NoError(t, err)
		assert.Equal(t, DefaultCodeLength, len(mockAuthCode.GetCode()))
		assert.Nil(t, mockAuthCode.GetExtraData())
	})

	t.Run("error_when_client_is_nil", func(t *testing.T) {
		r := newReq()
		r.Client = nil

		err := New(NewOptions()).Generate(context.Background(), &sql.AuthorizationCode{}, r)
		assert.ErrorIs(t, err, ErrNilClient)
	})

	t.Run("error_when_user_is_nil", func(t *testing.T) {
		r := newReq()
		r.User = nil

		err := New(NewOptions()).Generate(context.Background(), &sql.AuthorizationCode{}, r)
		assert.ErrorIs(t, err, ErrNilUser)
	})

	t.Run("error_when_extra_data_generator_fails", func(t *testing.T) {
		r := newReq()
		extraDataGen := codegen.NewMockExtraDataGenerator(t)
		extraDataGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("*requests.AuthorizationRequest")).Return(nil, errors.New("store error")).Once()

		g := New(NewOptions().SetExtraDataGenerator(extraDataGen.Execute))
		err := g.Generate(context.Background(), &sql.AuthorizationCode{}, r)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "store error")
	})
}

func TestGenerator_genCode(t *testing.T) {
	mockClient := &sql.Client{}

	t.Run("success_with_custom_generator", func(t *testing.T) {
		strGen := codegen.NewMockRandStringGenerator(t)
		expected := "thisIsARandomString"
		strGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("types.GrantType"), mock.AnythingOfType("*sql.Client")).Return(expected, nil).Once()

		g := New(NewOptions().SetRandStringGenerator(strGen.Execute))
		s, err := g.genCode(context.Background(), types.GrantTypeAuthorizationCode, mockClient)
		assert.NoError(t, err)
		assert.Equal(t, expected, s)
	})

	t.Run("error_from_custom_generator", func(t *testing.T) {
		strGen := codegen.NewMockRandStringGenerator(t)
		strGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("types.GrantType"), mock.AnythingOfType("*sql.Client")).Return("", errors.New("entropy error")).Once()

		g := New(NewOptions().SetRandStringGenerator(strGen.Execute))
		_, err := g.genCode(context.Background(), types.GrantTypeAuthorizationCode, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "entropy error")
	})

	t.Run("success_with_default_generator", func(t *testing.T) {
		g := New(NewOptions())
		s, err := g.genCode(context.Background(), types.GrantTypeAuthorizationCode, mockClient)
		assert.NoError(t, err)
		assert.Equal(t, DefaultCodeLength, len(s))
	})

	t.Run("error_when_code_length_is_zero", func(t *testing.T) {
		g := New(NewOptions())
		g.codeLength = 0
		_, err := g.genCode(context.Background(), types.GrantTypeAuthorizationCode, mockClient)
		assert.ErrorIs(t, err, ErrInvalidCodeLength)
	})
}

func TestGenerator_expiresInHandler(t *testing.T) {
	expInGen := codegen.NewMockExpiresInGenerator(t)
	expected := 10 * time.Minute
	expInGen.EXPECT().Execute(mock.Anything, mock.AnythingOfType("types.GrantType"), mock.AnythingOfType("*sql.Client")).Return(expected).Once()

	mockClient := &sql.Client{}
	g := New(NewOptions().SetExpiresInGenerator(expInGen.Execute))
	exp := g.expiresInHandler(context.Background(), types.GrantTypeAuthorizationCode, mockClient)
	assert.Equal(t, expected, exp)

	expected = 30 * time.Minute
	g.SetExpiresInGenerator(nil)
	g.SetExpiresIn(expected)
	exp = g.expiresInHandler(context.Background(), types.GrantTypeAuthorizationCode, mockClient)
	assert.Equal(t, expected, exp)
}
