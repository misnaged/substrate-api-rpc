package rpc

import (
	"fmt"
	scalecodec "github.com/itering/scale.go"
	"github.com/itering/scale.go/types"
	"github.com/itering/scale.go/utiles"
	"github.com/misnaged/substrate-api-rpc/hasher"
	"github.com/misnaged/substrate-api-rpc/keyring"
	"github.com/misnaged/substrate-api-rpc/model"
	"github.com/misnaged/substrate-api-rpc/util"
)

type ICustomTranscation interface {
	SignTransactionCustom() (string, error)
}

func NewCustomTransaction(
	callIndex, genesisHash string,
	nonce int,
	version *model.RuntimeVersion,
	meta *types.MetadataStruct,
	kr keyring.IKeyRing,
	scaleDecOpts *types.ScaleDecoderOption,
	params []scalecodec.ExtrinsicParam) ICustomTranscation {
	return &CustomTransaction{
		CallIndex:        callIndex,
		GenesisHash:      genesisHash,
		Nonce:            nonce,
		RuntimeVersion:   version,
		Meta:             meta,
		Keyring:          kr,
		ScaleDecoderOpts: scaleDecOpts,
		Params:           params,
	}
}

type CustomTransaction struct {
	CallIndex,
	GenesisHash string
	Nonce            int
	RuntimeVersion   *model.RuntimeVersion
	Meta             *types.MetadataStruct
	Keyring          keyring.IKeyRing
	ScaleDecoderOpts *types.ScaleDecoderOption
	Params           []scalecodec.ExtrinsicParam
}

func (customTx *CustomTransaction) GetEncodedCall() string {
	return types.EncodeWithOpt("Call", map[string]interface{}{"call_index": customTx.CallIndex, "params": customTx.Params}, customTx.ScaleDecoderOpts)
}

func (customTx *CustomTransaction) SignTransactionCustom() (string, error) {
	genericExtrinsic := &scalecodec.GenericExtrinsic{
		VersionInfo: TxVersionInfo,
		Signer:      map[string]interface{}{"Id": customTx.Keyring.PublicKey()},
		Era:         "00",
		Nonce:       customTx.Nonce,
		Params:      customTx.Params,
		CallCode:    customTx.CallIndex,
	}

	genericExtrinsic.SignedExtensions = make(map[string]interface{})
	if util.StringInSlice("ChargeAssetTxPayment", customTx.ScaleDecoderOpts.Metadata.Extrinsic.SignedIdentifier) {
		genericExtrinsic.SignedExtensions["ChargeAssetTxPayment"] = map[string]interface{}{"tip": 0, "asset_id": nil}
	}
	if util.StringInSlice("CheckMetadataHash", customTx.ScaleDecoderOpts.Metadata.Extrinsic.SignedIdentifier) {
		genericExtrinsic.SignedExtensions["CheckMetadataHash"] = "Disabled"
	}
	payload, err := customTx.buildExtrinsicPayload(genericExtrinsic)
	if err != nil {
		return "", fmt.Errorf("failed to build extrinsic payload: %v", err)
	}

	if len(util.HexToBytes(payload)) > 256 {
		payload = util.BytesToHex(hasher.HashByCryptoName(util.HexToBytes(payload), "Blake2_256"))
	}
	genericExtrinsic.SignatureRaw = map[string]interface{}{string(customTx.Keyring.Type()): utiles.AddHex(customTx.Keyring.Sign(util.AddHex(payload)))}

	encodedExtrinsic, err := genericExtrinsic.Encode(customTx.ScaleDecoderOpts)
	if err != nil {
		return "", fmt.Errorf("failed to encode extrinsic: %w", err)
	}
	return util.AddHex(encodedExtrinsic), nil
}

func (customTx *CustomTransaction) buildExtrinsicPayload(genericExtrinsic *scalecodec.GenericExtrinsic) (string, error) {

	data := customTx.GetEncodedCall()
	data = data + types.Encode("EraExtrinsic", genericExtrinsic.Era)   // era
	data = data + types.Encode("Compact<U32>", genericExtrinsic.Nonce) // nonce
	if len(customTx.Meta.Extrinsic.SignedIdentifier) > 0 && utiles.SliceIndex("ChargeTransactionPayment", customTx.Meta.Extrinsic.SignedIdentifier) > -1 {
		data = data + types.Encode("Compact<Balance>", genericExtrinsic.Tip) // tip
	}

	for identifier, extension := range genericExtrinsic.SignedExtensions {
		for _, ext := range customTx.Meta.Extrinsic.SignedExtensions {
			if ext.Identifier == identifier {
				data = data + types.Encode(ext.TypeString, extension)
			}
		}
	}
	data = data + types.Encode("U32", customTx.RuntimeVersion.SpecVersion)        // specVersion
	data = data + types.Encode("U32", customTx.RuntimeVersion.TransactionVersion) // transactionVersion
	data = data + util.TrimHex(types.Encode("Hash", customTx.GenesisHash))        // genesisHash
	data = data + util.TrimHex(types.Encode("Hash", customTx.GenesisHash))        // blockHash

	if _, ok := genericExtrinsic.SignedExtensions["CheckMetadataHash"]; ok {
		data = data + util.TrimHex("00") // CheckMetadataHash
	}
	return data, nil
}
