package substrate

import (
	"fmt"

	scale "github.com/itering/scale.go"
	"github.com/itering/scale.go/types"
	"github.com/itering/scale.go/types/scaleBytes"
	"github.com/misnaged/substrate-api-rpc/metadata"
	"github.com/misnaged/substrate-api-rpc/util"
)

// DecodeEvent Event decode
func DecodeEvent(rawList string, metadata *metadata.Instant, spec int) (r interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Recovering from panic in DecodeEvent error is: %v \n", r)
		}
	}()
	m := types.MetadataStruct(*metadata)
	e := scale.EventsDecoder{}
	option := types.ScaleDecoderOption{Metadata: &m, Spec: spec}
	e.Init(scaleBytes.ScaleBytes{Data: util.HexToBytes(rawList)}, &option)
	e.Process()
	return e.Value, nil
}
