package transformer

import (
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

/* Transformer specific functions */

func init() {
	XlateFuncBind("DbToYang_media_fec_mode_state_xfmr", DbToYang_media_fec_mode_state_xfmr)
	XlateFuncBind("DbToYang_media_fec_mode_xfmr", DbToYang_media_fec_mode_xfmr)
	XlateFuncBind("YangToDb_media_fec_mode_xfmr", YangToDb_media_fec_mode_xfmr)
	XlateFuncBind("YangToDb_media_fec_mode_key_xfmr", YangToDb_media_fec_mode_key_xfmr)
}

func getMediaFecRoot(s *ygot.GoStruct) map[string]*ocbinds.OpenconfigPlatform_Components_Component {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Components.Component

}

var DbToYang_media_fec_mode_state_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_media_fec_mode_state_xfmr key: ", inParams.key, " Xpath: ", inParams.uri)
	inval = data["PORT_TABLE"][inParams.key].Field["media-fec-mode"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["media-fec-mode"] = outval
	}

	return result, err
}

var DbToYang_media_fec_mode_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_media_fec_mode_xfmr key: ", inParams.key, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["PORT"][inParams.key].Field["media-fec-mode"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["media-fec-mode"] = outval
	}

	return result, err
}

var YangToDb_media_fec_mode_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error

	pathInfo := NewPathInfo(inParams.uri)
	portName := pathInfo.Var("name")
	ifName := getIfPortName(portName)

	return ifName, err
}

var YangToDb_media_fec_mode_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var field string
	var inval ocbinds.E_OpenconfigPortMediaFecExt_MediaFecModeType
	if inParams.param == nil {
		res_map["media-fec-mode"] = ""
		return res_map, err
	}
	if inParams.oper == DELETE {
		res_map["media-fec-mode"] = ""
		return res_map, nil
	}

	log.Info("yangtodb_media_fec_mode_xfmr : ", *inParams.ygRoot, " xpath: ", inParams.uri)
	log.Info("yangtodb_media_fec_mode_xfmr inParams.key: ", inParams.key)

	mediaFecObj := getMediaFecRoot(inParams.ygRoot)
	if mediaFecObj == nil || len(mediaFecObj) < 1 {
		log.Info("YangToDb_media_fec_modex_xfmr: Empty component.")
		return res_map, tlerr.NotSupported("media fec mode is not supported")
	}
	pathInfo := NewPathInfo(inParams.uri)
	log.Warning("media fec mode   Path:", pathInfo)
	log.Warning("media fec mode   Platform Object : ", mediaFecObj[pathInfo.Var("name")])

	inval = mediaFecObj[pathInfo.Var("name")].Port.Config.MediaFecMode
	field = "media-fec-mode"

	outval := ""
	switch inval {
	case ocbinds.OpenconfigPortMediaFecExt_MediaFecModeType_IEEE:
		outval = "ieee"
	case ocbinds.OpenconfigPortMediaFecExt_MediaFecModeType_CUSTOM:
		outval = "custom"
	}

	log.Info("yangtodb_media_fec enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}
