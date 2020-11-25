package custom_validation

// ValidateNtpVrf check if Mgmt VRF is configured when mgmt is set as Mgmt VRF
// Path : /sonic-system-ntp/NTP/NTP_LIST/vrf
// Returns - CVL Error object
func (t *CustomValidation) ValidateNtpVrf(
        vc *CustValidationCtxt) CVLErrorInfo {

        if (vc.CurCfg.VOp == OP_DELETE) {
                return CVLErrorInfo{ErrCode: CVL_SUCCESS}
        }

        if (vc.YNodeVal != "mgmt")  {
                return CVLErrorInfo{ErrCode: CVL_SUCCESS}
        }

        entry, err := vc.RClient.HGetAll("MGMT_VRF_CONFIG|vrf_global").Result()
        if ((len(entry) == 0) || (err != nil)) {
                return CVLErrorInfo {
                       ErrCode :         CVL_SEMANTIC_ERROR,
                       TableName:        "NTP", 
                       Keys:             []string{"global"},
                       ConstraintErrMsg: "Management VRF not configured",
                }
        }

        enabled, found_field := entry["mgmtVrfEnabled"];
        if (!found_field) {
                return CVLErrorInfo {
                       ErrCode :         CVL_SEMANTIC_ERROR,
                       TableName:        "NTP",
                       Keys:             []string{"global"},
                       ConstraintErrMsg: "Management VRF not configured",
                }

        }

        if enabled != "true" {
                return CVLErrorInfo {
                        ErrCode :         CVL_SEMANTIC_ERROR,
                        TableName:        "NTP", 
                        Keys:             []string{"global"},
                        ConstraintErrMsg: "Management VRF not enabled",
                }
        }

        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
