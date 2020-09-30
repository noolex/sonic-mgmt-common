package custom_validation

import (
    "strings"
    log "github.com/golang/glog"
)

func (t *CustomValidation) ValidateIpPrefixListCfg(vc *CustValidationCtxt) CVLErrorInfo {
    if (vc.CurCfg.VOp != OP_CREATE) {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    keyArr := strings.Split(vc.CurCfg.Key, "|")
    if (len(keyArr) != 5) {
        errMsg := "Internal error !"
        log.Info (errMsg, " ==> Invalid Key length! Key : ", vc.CurCfg.Key)
        return CVLErrorInfo{
             ErrCode: CVL_SEMANTIC_ERROR,
             TableName: "PREFIX",
             Keys: keyArr,
             ErrAppTag: "internal-error",
             ConstraintErrMsg: errMsg,
        }
    }

    tblName := keyArr[0]
    prefixSetName := keyArr[1]
    seqNo := keyArr[2]
    ipPrefix := keyArr[3]
    maskLengthRange := keyArr[4]

    if tableKeys, err:= vc.RClient.Keys(tblName + "|" + prefixSetName + "|" + seqNo + "|*").Result() ; ((err == nil) && (len(tableKeys) != 0)) {
        errMsg := "Same sequence-number already exists with different IP-prefix & masklength-range !"
        log.Info (errMsg, " ==> Key : ", tableKeys, " already exists ! Can't create new Key : [", vc.CurCfg.Key, "]")
        return CVLErrorInfo{
             ErrCode: CVL_SEMANTIC_ERROR,
             TableName: "PREFIX",
             Keys: keyArr,
             ErrAppTag: "same-seq-no-exists-with-diff-ip-prefix-and-masklength-range",
             ConstraintErrMsg: errMsg,
        }
    }

    if tableKeys, err:= vc.RClient.Keys(tblName + "|" + prefixSetName + "|*|" + ipPrefix + "|" + maskLengthRange).Result() ; ((err == nil) && (len(tableKeys) != 0)) {
        errMsg := "Same IP-prefix & masklength-range already exists with different sequence-number !"
        log.Info (errMsg, " ==> Key : ", tableKeys, " already exists ! Can't create new Key : [", vc.CurCfg.Key, "]")
        return CVLErrorInfo{
             ErrCode: CVL_SEMANTIC_ERROR,
             TableName: "PREFIX",
             Keys: keyArr,
             ErrAppTag: "same-ip-prefix-and-masklength-range-exists-with-diff-seq-no",
             ConstraintErrMsg: errMsg,
        }
    }

    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
