//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: protob/ecdsa-accsigning.proto

package accsigning

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Represents a P2P message sent to each party during Round 1 of the Accountable ECDSA TSS signing protocol.
type SignRound1Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RangeProofAlice [][]byte `protobuf:"bytes,1,rep,name=range_proof_alice,json=rangeProofAlice,proto3" json:"range_proof_alice,omitempty"`
	ProofXGamma     [][]byte `protobuf:"bytes,2,rep,name=proof_x_gamma,json=proofXGamma,proto3" json:"proof_x_gamma,omitempty"`
	ProofXKw        [][]byte `protobuf:"bytes,3,rep,name=proof_x_kw,json=proofXKw,proto3" json:"proof_x_kw,omitempty"`
}

func (x *SignRound1Message1) Reset() {
	*x = SignRound1Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message1) ProtoMessage() {}

func (x *SignRound1Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message1.ProtoReflect.Descriptor instead.
func (*SignRound1Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{0}
}

func (x *SignRound1Message1) GetRangeProofAlice() [][]byte {
	if x != nil {
		return x.RangeProofAlice
	}
	return nil
}

func (x *SignRound1Message1) GetProofXGamma() [][]byte {
	if x != nil {
		return x.ProofXGamma
	}
	return nil
}

func (x *SignRound1Message1) GetProofXKw() [][]byte {
	if x != nil {
		return x.ProofXKw
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 1 of the Accountable ECDSA TSS signing protocol.
type SignRound1Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CA           []byte   `protobuf:"bytes,1,opt,name=c_a,json=cA,proto3" json:"c_a,omitempty"`
	XGamma       []byte   `protobuf:"bytes,2,opt,name=x_gamma,json=xGamma,proto3" json:"x_gamma,omitempty"`
	XKgamma      []byte   `protobuf:"bytes,3,opt,name=x_kgamma,json=xKgamma,proto3" json:"x_kgamma,omitempty"`
	XKw          []byte   `protobuf:"bytes,4,opt,name=x_kw,json=xKw,proto3" json:"x_kw,omitempty"`
	ProofXKgamma [][]byte `protobuf:"bytes,5,rep,name=proof_x_kgamma,json=proofXKgamma,proto3" json:"proof_x_kgamma,omitempty"`
}

func (x *SignRound1Message2) Reset() {
	*x = SignRound1Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound1Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound1Message2) ProtoMessage() {}

func (x *SignRound1Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound1Message2.ProtoReflect.Descriptor instead.
func (*SignRound1Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{1}
}

func (x *SignRound1Message2) GetCA() []byte {
	if x != nil {
		return x.CA
	}
	return nil
}

func (x *SignRound1Message2) GetXGamma() []byte {
	if x != nil {
		return x.XGamma
	}
	return nil
}

func (x *SignRound1Message2) GetXKgamma() []byte {
	if x != nil {
		return x.XKgamma
	}
	return nil
}

func (x *SignRound1Message2) GetXKw() []byte {
	if x != nil {
		return x.XKw
	}
	return nil
}

func (x *SignRound1Message2) GetProofXKgamma() [][]byte {
	if x != nil {
		return x.ProofXKgamma
	}
	return nil
}

// Represents a P2P message sent to each party during Round 2 of the Accountable ECDSA TSS signing protocol.
type SignRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CGamma  []byte   `protobuf:"bytes,1,opt,name=c_gamma,json=cGamma,proto3" json:"c_gamma,omitempty"`
	CW      []byte   `protobuf:"bytes,2,opt,name=c_w,json=cW,proto3" json:"c_w,omitempty"`
	ProofP  [][]byte `protobuf:"bytes,3,rep,name=proof_p,json=proofP,proto3" json:"proof_p,omitempty"`
	ProofDl [][]byte `protobuf:"bytes,4,rep,name=proof_dl,json=proofDl,proto3" json:"proof_dl,omitempty"`
}

func (x *SignRound2Message1) Reset() {
	*x = SignRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message1) ProtoMessage() {}

func (x *SignRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message1.ProtoReflect.Descriptor instead.
func (*SignRound2Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{2}
}

func (x *SignRound2Message1) GetCGamma() []byte {
	if x != nil {
		return x.CGamma
	}
	return nil
}

func (x *SignRound2Message1) GetCW() []byte {
	if x != nil {
		return x.CW
	}
	return nil
}

func (x *SignRound2Message1) GetProofP() [][]byte {
	if x != nil {
		return x.ProofP
	}
	return nil
}

func (x *SignRound2Message1) GetProofDl() [][]byte {
	if x != nil {
		return x.ProofDl
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 2 of the Accountable ECDSA TSS signing protocol.
type SignRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Recipient []byte   `protobuf:"bytes,1,opt,name=recipient,proto3" json:"recipient,omitempty"`
	CAlpha    []byte   `protobuf:"bytes,2,opt,name=c_alpha,json=cAlpha,proto3" json:"c_alpha,omitempty"`
	CBeta     []byte   `protobuf:"bytes,3,opt,name=c_beta,json=cBeta,proto3" json:"c_beta,omitempty"`
	CBetaPrm  []byte   `protobuf:"bytes,4,opt,name=c_beta_prm,json=cBetaPrm,proto3" json:"c_beta_prm,omitempty"`
	CMu       []byte   `protobuf:"bytes,5,opt,name=c_mu,json=cMu,proto3" json:"c_mu,omitempty"`
	CNu       []byte   `protobuf:"bytes,6,opt,name=c_nu,json=cNu,proto3" json:"c_nu,omitempty"`
	CNuPrm    []byte   `protobuf:"bytes,7,opt,name=c_nu_prm,json=cNuPrm,proto3" json:"c_nu_prm,omitempty"`
	ProofP    [][]byte `protobuf:"bytes,8,rep,name=proof_p,json=proofP,proto3" json:"proof_p,omitempty"`
	ProofDl   [][]byte `protobuf:"bytes,9,rep,name=proof_dl,json=proofDl,proto3" json:"proof_dl,omitempty"`
	ProofBeta [][]byte `protobuf:"bytes,10,rep,name=proof_beta,json=proofBeta,proto3" json:"proof_beta,omitempty"`
	ProofNu   [][]byte `protobuf:"bytes,11,rep,name=proof_nu,json=proofNu,proto3" json:"proof_nu,omitempty"`
}

func (x *SignRound2Message) Reset() {
	*x = SignRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound2Message) ProtoMessage() {}

func (x *SignRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound2Message.ProtoReflect.Descriptor instead.
func (*SignRound2Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{3}
}

func (x *SignRound2Message) GetRecipient() []byte {
	if x != nil {
		return x.Recipient
	}
	return nil
}

func (x *SignRound2Message) GetCAlpha() []byte {
	if x != nil {
		return x.CAlpha
	}
	return nil
}

func (x *SignRound2Message) GetCBeta() []byte {
	if x != nil {
		return x.CBeta
	}
	return nil
}

func (x *SignRound2Message) GetCBetaPrm() []byte {
	if x != nil {
		return x.CBetaPrm
	}
	return nil
}

func (x *SignRound2Message) GetCMu() []byte {
	if x != nil {
		return x.CMu
	}
	return nil
}

func (x *SignRound2Message) GetCNu() []byte {
	if x != nil {
		return x.CNu
	}
	return nil
}

func (x *SignRound2Message) GetCNuPrm() []byte {
	if x != nil {
		return x.CNuPrm
	}
	return nil
}

func (x *SignRound2Message) GetProofP() [][]byte {
	if x != nil {
		return x.ProofP
	}
	return nil
}

func (x *SignRound2Message) GetProofDl() [][]byte {
	if x != nil {
		return x.ProofDl
	}
	return nil
}

func (x *SignRound2Message) GetProofBeta() [][]byte {
	if x != nil {
		return x.ProofBeta
	}
	return nil
}

func (x *SignRound2Message) GetProofNu() [][]byte {
	if x != nil {
		return x.ProofNu
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 3 of the Accountable ECDSA TSS signing protocol.
type SignRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Delta []byte   `protobuf:"bytes,1,opt,name=delta,proto3" json:"delta,omitempty"`
	D     []byte   `protobuf:"bytes,2,opt,name=d,proto3" json:"d,omitempty"`
	Proof [][]byte `protobuf:"bytes,3,rep,name=proof,proto3" json:"proof,omitempty"`
}

func (x *SignRound3Message) Reset() {
	*x = SignRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound3Message) ProtoMessage() {}

func (x *SignRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound3Message.ProtoReflect.Descriptor instead.
func (*SignRound3Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{4}
}

func (x *SignRound3Message) GetDelta() []byte {
	if x != nil {
		return x.Delta
	}
	return nil
}

func (x *SignRound3Message) GetD() []byte {
	if x != nil {
		return x.D
	}
	return nil
}

func (x *SignRound3Message) GetProof() [][]byte {
	if x != nil {
		return x.Proof
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 4 of the Accountable ECDSA TSS signing protocol.
type SignRound4Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Gamma [][]byte `protobuf:"bytes,1,rep,name=gamma,proto3" json:"gamma,omitempty"`
	Proof [][]byte `protobuf:"bytes,2,rep,name=proof,proto3" json:"proof,omitempty"`
}

func (x *SignRound4Message) Reset() {
	*x = SignRound4Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound4Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound4Message) ProtoMessage() {}

func (x *SignRound4Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound4Message.ProtoReflect.Descriptor instead.
func (*SignRound4Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{5}
}

func (x *SignRound4Message) GetGamma() [][]byte {
	if x != nil {
		return x.Gamma
	}
	return nil
}

func (x *SignRound4Message) GetProof() [][]byte {
	if x != nil {
		return x.Proof
	}
	return nil
}

// Represents a BROADCAST message sent to all parties during Round 4 of the Accountable ECDSA TSS signing protocol.
type SignRound5Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	S     []byte   `protobuf:"bytes,1,opt,name=s,proto3" json:"s,omitempty"`
	Proof [][]byte `protobuf:"bytes,2,rep,name=proof,proto3" json:"proof,omitempty"`
}

func (x *SignRound5Message) Reset() {
	*x = SignRound5Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_accsigning_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRound5Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRound5Message) ProtoMessage() {}

func (x *SignRound5Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_accsigning_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRound5Message.ProtoReflect.Descriptor instead.
func (*SignRound5Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_accsigning_proto_rawDescGZIP(), []int{6}
}

func (x *SignRound5Message) GetS() []byte {
	if x != nil {
		return x.S
	}
	return nil
}

func (x *SignRound5Message) GetProof() [][]byte {
	if x != nil {
		return x.Proof
	}
	return nil
}

var File_protob_ecdsa_accsigning_proto protoreflect.FileDescriptor

var file_protob_ecdsa_accsigning_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x61,
	0x63, 0x63, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x1f, 0x62, 0x69, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x2e, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e,
	0x65, 0x63, 0x64, 0x73, 0x61, 0x2e, 0x61, 0x63, 0x63, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x22, 0x82, 0x01, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x2a, 0x0a, 0x11, 0x72, 0x61, 0x6e, 0x67, 0x65,
	0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0c, 0x52, 0x0f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x41, 0x6c,
	0x69, 0x63, 0x65, 0x12, 0x22, 0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x78, 0x5f, 0x67,
	0x61, 0x6d, 0x6d, 0x61, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x58, 0x47, 0x61, 0x6d, 0x6d, 0x61, 0x12, 0x1c, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x5f, 0x78, 0x5f, 0x6b, 0x77, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x08, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x58, 0x4b, 0x77, 0x22, 0x92, 0x01, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x0f, 0x0a, 0x03,
	0x63, 0x5f, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x63, 0x41, 0x12, 0x17, 0x0a,
	0x07, 0x78, 0x5f, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06,
	0x78, 0x47, 0x61, 0x6d, 0x6d, 0x61, 0x12, 0x19, 0x0a, 0x08, 0x78, 0x5f, 0x6b, 0x67, 0x61, 0x6d,
	0x6d, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x78, 0x4b, 0x67, 0x61, 0x6d, 0x6d,
	0x61, 0x12, 0x11, 0x0a, 0x04, 0x78, 0x5f, 0x6b, 0x77, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x03, 0x78, 0x4b, 0x77, 0x12, 0x24, 0x0a, 0x0e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x78, 0x5f,
	0x6b, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0c, 0x70, 0x72,
	0x6f, 0x6f, 0x66, 0x58, 0x4b, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x22, 0x72, 0x0a, 0x12, 0x53, 0x69,
	0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31,
	0x12, 0x17, 0x0a, 0x07, 0x63, 0x5f, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x63, 0x47, 0x61, 0x6d, 0x6d, 0x61, 0x12, 0x0f, 0x0a, 0x03, 0x63, 0x5f, 0x77,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x63, 0x57, 0x12, 0x17, 0x0a, 0x07, 0x70, 0x72,
	0x6f, 0x6f, 0x66, 0x5f, 0x70, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x50, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x64, 0x6c, 0x18,
	0x04, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x44, 0x6c, 0x22, 0xad,
	0x02, 0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65,
	0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x63, 0x5f, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x63, 0x41, 0x6c, 0x70, 0x68, 0x61, 0x12, 0x15, 0x0a, 0x06, 0x63,
	0x5f, 0x62, 0x65, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x63, 0x42, 0x65,
	0x74, 0x61, 0x12, 0x1c, 0x0a, 0x0a, 0x63, 0x5f, 0x62, 0x65, 0x74, 0x61, 0x5f, 0x70, 0x72, 0x6d,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x63, 0x42, 0x65, 0x74, 0x61, 0x50, 0x72, 0x6d,
	0x12, 0x11, 0x0a, 0x04, 0x63, 0x5f, 0x6d, 0x75, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x63, 0x4d, 0x75, 0x12, 0x11, 0x0a, 0x04, 0x63, 0x5f, 0x6e, 0x75, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x03, 0x63, 0x4e, 0x75, 0x12, 0x18, 0x0a, 0x08, 0x63, 0x5f, 0x6e, 0x75, 0x5f, 0x70,
	0x72, 0x6d, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x63, 0x4e, 0x75, 0x50, 0x72, 0x6d,
	0x12, 0x17, 0x0a, 0x07, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x70, 0x18, 0x08, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x06, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x50, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x5f, 0x64, 0x6c, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x44, 0x6c, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x62, 0x65,
	0x74, 0x61, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x42,
	0x65, 0x74, 0x61, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x6e, 0x75, 0x18,
	0x0b, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x4e, 0x75, 0x22, 0x4d,
	0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x0c, 0x0a, 0x01, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x3f, 0x0a,
	0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x05, 0x67, 0x61, 0x6d, 0x6d, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x37,
	0x0a, 0x11, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x35, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x12, 0x0c, 0x0a, 0x01, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01,
	0x73, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x12, 0x5a, 0x10, 0x65, 0x63, 0x64, 0x73, 0x61,
	0x2f, 0x61, 0x63, 0x63, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_accsigning_proto_rawDescOnce sync.Once
	file_protob_ecdsa_accsigning_proto_rawDescData = file_protob_ecdsa_accsigning_proto_rawDesc
)

func file_protob_ecdsa_accsigning_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_accsigning_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_accsigning_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_accsigning_proto_rawDescData)
	})
	return file_protob_ecdsa_accsigning_proto_rawDescData
}

var file_protob_ecdsa_accsigning_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_protob_ecdsa_accsigning_proto_goTypes = []interface{}{
	(*SignRound1Message1)(nil), // 0: binance.tsslib.ecdsa.accsigning.SignRound1Message1
	(*SignRound1Message2)(nil), // 1: binance.tsslib.ecdsa.accsigning.SignRound1Message2
	(*SignRound2Message1)(nil), // 2: binance.tsslib.ecdsa.accsigning.SignRound2Message1
	(*SignRound2Message)(nil),  // 3: binance.tsslib.ecdsa.accsigning.SignRound2Message
	(*SignRound3Message)(nil),  // 4: binance.tsslib.ecdsa.accsigning.SignRound3Message
	(*SignRound4Message)(nil),  // 5: binance.tsslib.ecdsa.accsigning.SignRound4Message
	(*SignRound5Message)(nil),  // 6: binance.tsslib.ecdsa.accsigning.SignRound5Message
}
var file_protob_ecdsa_accsigning_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_accsigning_proto_init() }
func file_protob_ecdsa_accsigning_proto_init() {
	if File_protob_ecdsa_accsigning_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_accsigning_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_accsigning_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound1Message2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_accsigning_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message1); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_accsigning_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound2Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_accsigning_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound3Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_accsigning_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound4Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_ecdsa_accsigning_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRound5Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_ecdsa_accsigning_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_accsigning_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_accsigning_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_accsigning_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_accsigning_proto = out.File
	file_protob_ecdsa_accsigning_proto_rawDesc = nil
	file_protob_ecdsa_accsigning_proto_goTypes = nil
	file_protob_ecdsa_accsigning_proto_depIdxs = nil
}
