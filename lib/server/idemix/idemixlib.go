/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"github.com/hyperledger/fabric-amcl/amcl"
	fp256bn "github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/hyperledger/fabric/idemix"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

// Lib represents idemix library
type Lib interface {
	NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (ik *idemix.IssuerKey, err error)
	NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (cred *idemix.Credential, err error)
	CreateCRI(key *sm2.PrivateKey, unrevokedHandles []*fp256bn.BIG, epoch int, alg idemix.RevocationAlgorithm, rng *amcl.RAND) (cri *idemix.CredentialRevocationInformation, err error)
	GenerateLongTermRevocationKey() (pk *sm2.PrivateKey, err error)
	GetRand() (rand *amcl.RAND, err error)
	RandModOrder(rng *amcl.RAND) (big *fp256bn.BIG, err error)
}

// libImpl is adapter for idemix library. It implements Lib interface
type libImpl struct{}

// NewLib returns an instance of an object that implements Lib interface
func NewLib() Lib {
	return &libImpl{}
}

func (i *libImpl) GetRand() (rand *amcl.RAND, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return idemix.GetRand()
}
func (i *libImpl) NewCredential(key *idemix.IssuerKey, m *idemix.CredRequest, attrs []*fp256bn.BIG, rng *amcl.RAND) (cred *idemix.Credential, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return idemix.NewCredential(key, m, attrs, rng)
}
func (i *libImpl) RandModOrder(rng *amcl.RAND) (big *fp256bn.BIG, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return idemix.RandModOrder(rng), nil
}
func (i *libImpl) NewIssuerKey(AttributeNames []string, rng *amcl.RAND) (ik *idemix.IssuerKey, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return idemix.NewIssuerKey(AttributeNames, rng)
}
func (i *libImpl) CreateCRI(key *sm2.PrivateKey, unrevokedHandles []*fp256bn.BIG, epoch int, alg idemix.RevocationAlgorithm, rng *amcl.RAND) (cri *idemix.CredentialRevocationInformation, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return idemix.CreateCRI(key, unrevokedHandles, epoch, alg, rng)
}
func (i *libImpl) GenerateLongTermRevocationKey() (pk *sm2.PrivateKey, err error) {
	defer func() {
		r := recover()
		if r != nil {
			err = errors.Errorf("failure: %s", r)
		}
	}()
	return idemix.GenerateLongTermRevocationKey()
}
