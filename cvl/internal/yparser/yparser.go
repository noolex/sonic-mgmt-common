////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package yparser

/* Yang parser using libyang library */

import (
	"os"
	"fmt"
	"strings"
	//lint:ignore ST1001 This is safe to dot import for util package
	. "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	"unsafe"
)

/*
#cgo LDFLAGS: -lyang
#include <libyang/libyang.h>
#include <libyang/tree_data.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int lyd_check_mandatory_tree(struct lyd_node *root, struct ly_ctx *ctx, const struct lys_module **modules, int mod_count, int options);

struct lyd_node* lyd_parse_data_path(struct ly_ctx *ctx,  const char *path, LYD_FORMAT format, int options) {
	return lyd_parse_path(ctx, path, format, options);
}

struct lyd_node *lyd_parse_data_mem(struct ly_ctx *ctx, const char *data, LYD_FORMAT format, int options)
{
	return lyd_parse_mem(ctx, data, format, options);
}

int lyd_data_validate(struct lyd_node **node, int options, struct ly_ctx *ctx)
{
	int ret = -1;

	//Check mandatory elements as it is skipped for LYD_OPT_EDIT
	ret = lyd_check_mandatory_tree(*node, ctx, NULL, 0, LYD_OPT_CONFIG | LYD_OPT_NOEXTDEPS);

	if (ret != 0)
	{
		return ret;
	}

	return lyd_validate(node, options, ctx);
}

struct leaf_value {
	const char *name;
	const char *value;
};

int lyd_multi_new_leaf(struct lyd_node *parent, const struct lys_module *module,
	struct leaf_value *leafValArr, int size)
{
        const char *name, *val;
	struct lyd_node *leaf;
	struct lys_type *type = NULL;
	int has_ptr_type = 0;
	int idx = 0;

	for (idx = 0; idx < size; idx++)
	{
		if ((leafValArr[idx].name == NULL) || (leafValArr[idx].value == NULL))
		{
			continue;
		}

		name = leafValArr[idx].name;
		val = leafValArr[idx].value;

		if (NULL == (leaf = lyd_new_leaf(parent, module, name, val)))
		{
			return -1;
		}

		//Validate all union types as it is skipped for LYD_OPT_EDIT
		if (((struct lys_node_leaflist*)leaf->schema)->type.base == LY_TYPE_UNION)
		{
			type = &((struct lys_node_leaflist*)leaf->schema)->type;

			//save the has_ptr_type field
			has_ptr_type = type->info.uni.has_ptr_type;

			//Work around, set to 0 to check all union types
			type->info.uni.has_ptr_type = 0;

			if (lyd_validate_value(leaf->schema, val))
			{
				return -1;
			}

			//Restore has_ptr_type
			type->info.uni.has_ptr_type = has_ptr_type;
		}
	}

	return 0;
}

struct lyd_node *lyd_find_node(struct lyd_node *root, const char *xpath)
{
	struct ly_set *set = NULL;
	struct lyd_node *node = NULL;

	if (root == NULL)
	{
		return NULL;
	}

	set = lyd_find_path(root, xpath);
	if (set == NULL || set->number == 0) {
		return  NULL;
	}

	node = set->set.d[0];
	ly_set_free(set);

	return node;
}

int lyd_node_leafref_match_in_union(struct lys_module *module, const char *xpath, const char *value)
{
	struct ly_set *set = NULL;
	struct lys_node *node = NULL;
	int idx = 0;
	struct lys_node_leaflist* lNode;

	if (module == NULL)
	{
		return -1;
	}

	set = lys_find_path(module, NULL, xpath);
	if (set == NULL || set->number == 0) {
		return  -1;
	}

	node = set->set.s[0];
	ly_set_free(set);

	//Now check if it matches with any leafref node
	lNode = (struct lys_node_leaflist*)node;

	for (idx = 0; idx < lNode->type.info.uni.count; idx++)
	{
		if (lNode->type.info.uni.types[idx].base != LY_TYPE_LEAFREF)
		{
			//Look for leafref type only
			continue;
		}

		if (0 == lyd_validate_value((struct lys_node*)
		    lNode->type.info.uni.types[idx].info.lref.target, value))
		{
			return 0;
		}
	}

	return -1;
}

struct lys_node* lys_get_snode(struct ly_set *set, int idx) {
	if (set == NULL || set->number == 0) {
		return NULL;
	}

	return set->set.s[idx];
}

int lyd_change_leaf_data(struct lyd_node *leaf, const char *val_str) {
  return lyd_change_leaf((struct lyd_node_leaf_list *)leaf, val_str);
}

struct lys_leaf_ref_path {
	const char *path[10]; //max 10 path
	int count; //actual path count
};

const char *nonLeafRef = "non-leafref";
struct lys_leaf_ref_path* lys_get_leafrefs(struct lys_node_leaf *node) {
	static struct lys_leaf_ref_path leafrefs;
	memset(&leafrefs, 0, sizeof(leafrefs));

	int nonLeafRefCnt = 0;

	if (node->type.base == LY_TYPE_LEAFREF) {
		leafrefs.path[0] = node->type.info.lref.path;
		leafrefs.count = 1;

	} else if (node->type.base == LY_TYPE_UNION) {
		int typeCnt = 0;
		for (; typeCnt < node->type.info.uni.count; typeCnt++) {
			if (node->type.info.uni.types[typeCnt].base != LY_TYPE_LEAFREF) {
				if (nonLeafRefCnt == 0) {
					leafrefs.path[leafrefs.count] = nonLeafRef; //data type, not leafref
					leafrefs.count += 1;
					nonLeafRefCnt++;
				}

				continue;
			}

			leafrefs.path[leafrefs.count] = node->type.info.uni.types[typeCnt].info.lref.path;
			leafrefs.count += 1;
		}
	}

	if ((leafrefs.count - nonLeafRefCnt) > 0) {
		return &leafrefs;
	} else {
		return NULL;
	}
}

*/
import "C"

type YParserCtx C.struct_ly_ctx
type YParserNode C.struct_lyd_node
type YParserSNode C.struct_lys_node
type YParserModule C.struct_lys_module

var ypCtx *YParserCtx
var ypOpModule *YParserModule
var ypOpRoot *YParserNode  //Operation root
var ypOpNode *YParserNode  //Operation node

type XpathExpression struct {
	Expr string
	ErrCode string
	ErrStr string
}

type WhenExpression struct {
	Expr string //when expression
	NodeNames []string //node names under when condition
}

//YParserListInfo Important schema information to be loaded at bootup time
type YParserListInfo struct {
	ListName string
	Module *YParserModule
	DbName string
	ModelName string
	RedisTableName string //To which Redis table it belongs to, used for 1 Redis to N Yang List
	Keys []string
	RedisKeyDelim string
	RedisKeyPattern string
	RedisTableSize int
	MapLeaf []string //for 'mapping  list'
	LeafRef map[string][]string //for storing all leafrefs for a leaf in a table,
				//multiple leafref possible for union
	DfltLeafVal map[string]string //Default value for leaf/leaf-list
	XpathExpr map[string][]*XpathExpression
	CustValidation map[string][]string
	WhenExpr map[string][]*WhenExpression //multiple when expression for choice/case etc
	MandatoryNodes map[string]bool
	DependentOnTable string //for table on which it is dependent
}

type YParserLeafValue struct {
	Name string
	Value string
}

type YParser struct {
	//ctx *YParserCtx    //Parser context
	root *YParserNode    //Top evel root for validation
	operation string     //Edit operation
}

//YParserError YParser Error Structure
type YParserError struct {
	ErrCode  YParserRetCode   /* Error Code describing type of error. */
	Msg     string        /* Detailed error message. */
	ErrTxt  string        /* High level error message. */
	TableName string      /* List/Table having error */
	Keys    []string      /* Keys of the Table having error. */
        Field	string        /* Field Name throwing error . */
        Value	string        /* Field Value throwing error */
	ErrAppTag string      /* Error App Tag. */
}

type YParserRetCode int
const (
	YP_SUCCESS YParserRetCode = 1000 + iota
	YP_SYNTAX_ERROR
	YP_SEMANTIC_ERROR
	YP_SYNTAX_MISSING_FIELD
	YP_SYNTAX_INVALID_FIELD   /* Invalid Field  */
	YP_SYNTAX_INVALID_INPUT_DATA     /*Invalid Input Data */
	YP_SYNTAX_MULTIPLE_INSTANCE     /* Multiple Field Instances */
	YP_SYNTAX_DUPLICATE       /* Duplicate Fields  */
	YP_SYNTAX_ENUM_INVALID  /* Invalid enum value */
	YP_SYNTAX_ENUM_INVALID_NAME /* Invalid enum name  */
	YP_SYNTAX_ENUM_WHITESPACE     /* Enum name with leading/trailing whitespaces */
	YP_SYNTAX_OUT_OF_RANGE    /* Value out of range/length/pattern (data) */
	YP_SYNTAX_MINIMUM_INVALID       /* min-elements constraint not honored  */
	YP_SYNTAX_MAXIMUM_INVALID       /* max-elements constraint not honored */
	YP_SEMANTIC_DEPENDENT_DATA_MISSING   /* Dependent Data is missing */
	YP_SEMANTIC_MANDATORY_DATA_MISSING /* Mandatory Data is missing */
	YP_SEMANTIC_KEY_ALREADY_EXIST /* Key already existing */
	YP_SEMANTIC_KEY_NOT_EXIST /* Key is missing */
	YP_SEMANTIC_KEY_DUPLICATE  /* Duplicate key */
        YP_SEMANTIC_KEY_INVALID    /* Invalid key */
	YP_INTERNAL_UNKNOWN
)

const (
	YP_NOP = 1 + iota
	YP_OP_CREATE
	YP_OP_UPDATE
	YP_OP_DELETE
)

var yparserInitialized bool = false

func TRACE_LOG(tracelevel CVLTraceLevel, fmtStr string, args ...interface{}) {
	TRACE_LEVEL_LOG(tracelevel , fmtStr, args...)
}

func CVL_LOG(level CVLLogLevel, fmtStr string, args ...interface{}) {
	CVL_LEVEL_LOG(level, fmtStr, args...)
}

//package init function
func init() {
	if (os.Getenv("CVL_DEBUG") != "") {
		Debug(true)
	}
}

func Debug(on bool) {
	if  on {
		C.ly_verb(C.LY_LLDBG)
	} else {
		C.ly_verb(C.LY_LLERR)
	}
}

func Initialize() {
	if !yparserInitialized {
		ypCtx = (*YParserCtx)(C.ly_ctx_new(C.CString(CVL_SCHEMA), 0))
		C.ly_verb(C.LY_LLERR)
	//	yparserInitialized = true
	}
}

func Finish() {
	if yparserInitialized {
		C.ly_ctx_destroy((*C.struct_ly_ctx)(ypCtx), nil)
	//	yparserInitialized = false
	}
}

//ParseSchemaFile Parse YIN schema file
func ParseSchemaFile(modelFile string) (*YParserModule, YParserError) {
	module :=  C.lys_parse_path((*C.struct_ly_ctx)(ypCtx), C.CString(modelFile), C.LYS_IN_YIN)
	if module == nil {
		return nil, getErrorDetails()
	}

	if strings.Contains(modelFile, "sonic-common.yin") {
		ypOpModule = (*YParserModule)(module)
		ypOpRoot = (*YParserNode)(C.lyd_new(nil, (*C.struct_lys_module)(ypOpModule), C.CString("operation")))
		ypOpNode = (*YParserNode)(C.lyd_new_leaf((*C.struct_lyd_node)(ypOpRoot), (*C.struct_lys_module)(ypOpModule), C.CString("operation"), C.CString("NOP")))
	}

	return (*YParserModule)(module), YParserError {ErrCode : YP_SUCCESS,}
}

//AddChildNode Add child node to a parent node
func(yp *YParser) AddChildNode(module *YParserModule, parent *YParserNode, name string) *YParserNode {
	nameCStr :=  C.CString(name)
	defer C.free(unsafe.Pointer(nameCStr))
	ret := (*YParserNode)(C.lyd_new((*C.struct_lyd_node)(parent), (*C.struct_lys_module)(module), (*C.char)(nameCStr)))
	if (ret == nil) {
		TRACE_LOG(TRACE_YPARSER, "Failed parsing node %s", name)
	}

	return ret
}

//IsLeafrefMatchedInUnion Check if value matches with leafref node in union
func (yp *YParser) IsLeafrefMatchedInUnion(module *YParserModule, xpath, value string) bool {
	xpathCStr := C.CString(xpath)
	valCStr := C.CString(value)
	defer func() {
		C.free(unsafe.Pointer(xpathCStr))
		C.free(unsafe.Pointer(valCStr))
	}()
	return C.lyd_node_leafref_match_in_union((*C.struct_lys_module)(module), (*C.char)(xpathCStr), (*C.char)(valCStr)) == 0
}

//AddMultiLeafNodes dd child node to a parent node
func(yp *YParser) AddMultiLeafNodes(module *YParserModule, parent *YParserNode, multiLeaf []*YParserLeafValue) YParserError {

	leafValArr := make([]C.struct_leaf_value, len(multiLeaf))
	tmpArr := make([]*C.char, len(multiLeaf) * 2)

	size := C.int(0)
	for index := 0; index < len(multiLeaf); index++ {
		if (multiLeaf[index] == nil) || (multiLeaf[index].Name == "") {
			break
		}

		//Accumulate all name/value in array to be passed in lyd_multi_new_leaf()
		nameCStr := C.CString(multiLeaf[index].Name)
		valCStr := C.CString(multiLeaf[index].Value)
		leafValArr[index].name = (*C.char)(nameCStr)
		leafValArr[index].value = (*C.char)(valCStr)
		size++

		tmpArr = append(tmpArr, (*C.char)(nameCStr))
		tmpArr = append(tmpArr, (*C.char)(valCStr))
	}

	defer func() {
		for _, cStr := range tmpArr {
			C.free(unsafe.Pointer(cStr))
		}
	}()

	if C.lyd_multi_new_leaf((*C.struct_lyd_node)(parent), (*C.struct_lys_module)(module), (*C.struct_leaf_value)(unsafe.Pointer(&leafValArr[0])), size) != 0 {
		if Tracing {
			TRACE_LOG(TRACE_ONERROR, "Failed to create Multi Leaf Data = %v", multiLeaf)
		}
		return getErrorDetails()
	}

	return YParserError {ErrCode : YP_SUCCESS,}

}
//NodeDump Return entire subtree in XML format in string
func (yp *YParser) NodeDump(root *YParserNode) string {
	if (root == nil) {
		return ""
	} else {
		var outBuf *C.char
		C.lyd_print_mem(&outBuf, (*C.struct_lyd_node)(root), C.LYD_XML, C.LYP_WITHSIBLINGS)
		return C.GoString(outBuf)
	}
}

//MergeSubtree Merge source with destination
func (yp *YParser) MergeSubtree(root, node *YParserNode) (*YParserNode, YParserError) {
	rootTmp := (*C.struct_lyd_node)(root)

	if (root == nil || node == nil) {
		return root, YParserError {ErrCode: YP_SUCCESS}
	}

	if Tracing {
		rootdumpStr := yp.NodeDump((*YParserNode)(rootTmp))
		TRACE_LOG(TRACE_YPARSER, "Root subtree = %v\n", rootdumpStr)
	}

	if C.lyd_merge_to_ctx(&rootTmp, (*C.struct_lyd_node)(node), C.LYD_OPT_DESTRUCT, (*C.struct_ly_ctx)(ypCtx)) != 0 {
		return (*YParserNode)(rootTmp), getErrorDetails()
	}

	if Tracing {
		dumpStr := yp.NodeDump((*YParserNode)(rootTmp))
		TRACE_LOG(TRACE_YPARSER, "Merged subtree = %v\n", dumpStr)
	}

	return (*YParserNode)(rootTmp), YParserError {ErrCode : YP_SUCCESS,}
}

func (yp *YParser) DestroyCache() YParserError {

	if (yp.root != nil) {
		C.lyd_free_withsiblings((*C.struct_lyd_node)(yp.root))
		yp.root = nil
	}

	return YParserError {ErrCode : YP_SUCCESS,}
}

//SetOperation Set operation
func (yp *YParser) SetOperation(op string) YParserError {
	if (ypOpNode == nil) {
		return YParserError {ErrCode : YP_INTERNAL_UNKNOWN,}
	}

	if C.lyd_change_leaf_data((*C.struct_lyd_node)(ypOpNode), C.CString(op)) != 0 {
		return YParserError {ErrCode : YP_INTERNAL_UNKNOWN,}
	}

	yp.operation = op
	return YParserError {ErrCode : YP_SUCCESS,}
}

//ValidateSyntax Perform syntax checks
func (yp *YParser) ValidateSyntax(data, depData *YParserNode) YParserError {
	dataTmp := (*C.struct_lyd_node)(data)

	if (data != nil && depData != nil) {
		//merge ependent data for synatx validation - Update/Delete case
		if C.lyd_merge_to_ctx(&dataTmp, (*C.struct_lyd_node)(depData), C.LYD_OPT_DESTRUCT, (*C.struct_ly_ctx)(ypCtx)) != 0 {
			TRACE_LOG((TRACE_SYNTAX | TRACE_LIBYANG), "Unable to merge dependent data\n")
			return getErrorDetails()
		}
	}

	//Just validate syntax
	if C.lyd_data_validate(&dataTmp, C.LYD_OPT_EDIT | C.LYD_OPT_NOEXTDEPS, (*C.struct_ly_ctx)(ypCtx)) != 0 {
		if Tracing {
			strData := yp.NodeDump((*YParserNode)(dataTmp))
			TRACE_LOG(TRACE_ONERROR, "Failed to validate Syntax, data = %v", strData)
		}
		return  getErrorDetails()
	}

	return YParserError {ErrCode : YP_SUCCESS,}
}

func (yp *YParser) FreeNode(node *YParserNode) YParserError {
	if node != nil {
		C.lyd_free_withsiblings((*C.struct_lyd_node)(node))
		node = nil
	}

	return YParserError {ErrCode : YP_SUCCESS,}
}

/* This function translates LIBYANG error code to valid YPARSER error code. */
func translateLYErrToYParserErr(LYErrcode int) YParserRetCode {
	var ypErrCode YParserRetCode

	switch LYErrcode {
		case C.LYVE_SUCCESS:  /**< no error */
			ypErrCode = YP_SUCCESS
		case C.LYVE_XML_MISS, C.LYVE_INARG, C.LYVE_MISSELEM: /**< missing XML object */
			ypErrCode = YP_SYNTAX_MISSING_FIELD
		case C.LYVE_XML_INVAL, C.LYVE_XML_INCHAR, C.LYVE_INMOD, C.LYVE_INELEM , C.LYVE_INVAL, C.LYVE_MCASEDATA:/**< invalid XML object */
			ypErrCode = YP_SYNTAX_INVALID_FIELD
		case C.LYVE_EOF, C.LYVE_INSTMT,  C.LYVE_INPAR,  C.LYVE_INID,  C.LYVE_MISSSTMT, C.LYVE_MISSARG:   /**< invalid statement (schema) */
			ypErrCode = YP_SYNTAX_INVALID_INPUT_DATA
		case C.LYVE_TOOMANY:  /**< too many instances of some object */
			ypErrCode = YP_SYNTAX_MULTIPLE_INSTANCE
		case C.LYVE_DUPID,  C.LYVE_DUPLEAFLIST, C.LYVE_DUPLIST, C.LYVE_NOUNIQ:/**< duplicated identifier (schema) */
			ypErrCode = YP_SYNTAX_DUPLICATE
		case C.LYVE_ENUM_INVAL:    /**< invalid enum value (schema) */
			ypErrCode = YP_SYNTAX_ENUM_INVALID
		case C.LYVE_ENUM_INNAME:   /**< invalid enum name (schema) */
			ypErrCode = YP_SYNTAX_ENUM_INVALID_NAME
		case C.LYVE_ENUM_WS:  /**< enum name with leading/trailing whitespaces (schema) */
			ypErrCode = YP_SYNTAX_ENUM_WHITESPACE
		case C.LYVE_KEY_NLEAF,  C.LYVE_KEY_CONFIG, C.LYVE_KEY_TYPE : /**< list key is not a leaf (schema) */
			ypErrCode = YP_SEMANTIC_KEY_INVALID
		case C.LYVE_KEY_MISS, C.LYVE_PATH_MISSKEY: /**< list key not found (schema) */
			ypErrCode = YP_SEMANTIC_KEY_NOT_EXIST
		case C.LYVE_KEY_DUP:  /**< duplicated key identifier (schema) */
			ypErrCode = YP_SEMANTIC_KEY_DUPLICATE
		case C.LYVE_NOMIN:/**< min-elements constraint not honored (data) */
			ypErrCode = YP_SYNTAX_MINIMUM_INVALID
		case C.LYVE_NOMAX:/**< max-elements constraint not honored (data) */
			ypErrCode = YP_SYNTAX_MAXIMUM_INVALID
		case C.LYVE_NOMUST, C.LYVE_NOWHEN, C.LYVE_INWHEN, C.LYVE_NOLEAFREF :   /**< unsatisfied must condition (data) */
			ypErrCode = YP_SEMANTIC_DEPENDENT_DATA_MISSING
		case C.LYVE_NOMANDCHOICE:/**< max-elements constraint not honored (data) */
			ypErrCode = YP_SEMANTIC_MANDATORY_DATA_MISSING
		case C.LYVE_PATH_EXISTS:   /**< target node already exists (path) */
			ypErrCode = YP_SEMANTIC_KEY_ALREADY_EXIST
		default:
			ypErrCode = YP_INTERNAL_UNKNOWN

	}
	return ypErrCode
}

/* This function performs parsing and processing of LIBYANG error messages. */
func getErrorDetails() YParserError {
	var key []string
	var errtableName string
	var ElemVal string
	var errMessage string
	var ElemName string
	var errText string
	var msg string
	var ypErrCode YParserRetCode =  YP_INTERNAL_UNKNOWN
	var errMsg, errPath, errAppTag string

	ctx := (*C.struct_ly_ctx)(ypCtx)
	ypErrFirst := C.ly_err_first(ctx);


	if (ypErrFirst == nil) {
               return  YParserError {
                       TableName : errtableName,
                       ErrCode : ypErrCode,
                       Keys    : key,
                       Value : ElemVal,
                       Field : ElemName,
                       Msg        :  errMessage,
                       ErrTxt: errText,
                       ErrAppTag: errAppTag,
               }
       }


	if ((ypErrFirst != nil) && ypErrFirst.prev.no == C.LY_SUCCESS) {
		return YParserError {
			ErrCode : YP_SUCCESS,
		}
	}

	if (ypErrFirst != nil) {
	       errMsg = C.GoString(ypErrFirst.prev.msg)
	       errPath = C.GoString(ypErrFirst.prev.path)
	       errAppTag = C.GoString(ypErrFirst.prev.apptag)
	}


	/* Example error messages.
	1. Leafref "/sonic-port:sonic-port/sonic-port:PORT/sonic-port:ifname" of value "Ethernet668" points to a non-existing leaf.
	(path: /sonic-interface:sonic-interface/INTERFACE[portname='Ethernet668'][ip_prefix='10.0.0.0/31']/portname)
	2. A vlan interface member cannot be part of portchannel which is already a vlan member
	(path: /sonic-vlan:sonic-vlan/VLAN[name='Vlan1001']/members[.='Ethernet8'])
	3. Value "ch1" does not satisfy the constraint "Ethernet([1-3][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9])" (range, length, or pattern).
	(path: /sonic-vlan:sonic-vlan/VLAN[name='Vlan1001']/members[.='ch1'])*/


	/* Fetch the TABLE Name which are in CAPS. */
	resultTable := strings.SplitN(errPath, "[", 2)
	if (len(resultTable) >= 2) {
		resultTab := strings.Split(resultTable[0], "/")
		errtableName = resultTab[len(resultTab) -1]

		/* Fetch the Error Elem Name. */
		resultElem := strings.Split(resultTable[1], "/")
		ElemName = resultElem[len(resultElem) -1]
	}

	/* Fetch the invalid field name. */
	// errMsg is like: Invalid value "Port1" in "dst_port" element.
	result := strings.Split(errMsg, "\"")
	if (len(result) > 1) {
		for i := range result {
			if (strings.Contains(result[i], "value")) ||
			(strings.Contains(result[i], "Value")) {
				ElemVal = result[i+1]
			}

			if (strings.Contains(result[i], "element") || strings.Contains(result[i], "Element")) && (i > 0) {
				ElemName = result[i-1]
			}
		}
	} else if (len(result) == 1) {
		/* Custom contraint error message like in must statement.
		This can be used by App to display to user.
		*/
		errText = errMsg
	}

	// Find key elements
	resultKey := strings.Split(errPath, "=")
	for i := range resultKey {
		if (strings.Contains(resultKey[i], "]")) {
			newRes := strings.Split(resultKey[i], "]")
			key = append(key, newRes[0])
		}
	}

	/* Form the error message. */
	msg = "["
	for _, elem := range key {
		msg = msg + elem + " "
	}
	msg = msg + "]"

	/* For non-constraint related errors , print below error message. */
	if (len(result) > 1) {
		errMessage = errtableName + " with keys" + msg + " has field " +
		ElemName + " with invalid value " + ElemVal
	}else {
		/* Dependent data validation error. */
		errMessage = "Dependent data validation failed for table " +
		errtableName + " with keys" + msg
	}


	if (C.ly_errno == C.LY_EVALID) {  //Validation failure
		ypErrCode =  translateLYErrToYParserErr(int(ypErrFirst.prev.vecode))

	} else {
		switch (C.ly_errno) {
		case C.LY_EMEM:
			errText = "Memory allocation failure"

		case C.LY_ESYS:
			errText = "System call failure"

		case C.LY_EINVAL:
			errText = "Invalid value"

		case C.LY_EINT:
			errText = "Internal error"

		case C.LY_EPLUGIN:
			errText = "Error reported by a plugin"
		}
	}

	errObj := YParserError {
		TableName : errtableName,
		ErrCode : ypErrCode,
		Keys    : key,
		Value : ElemVal,
		Field : ElemName,
		Msg        :  errMessage,
		ErrTxt: errText,
		ErrAppTag: errAppTag,
	}

	TRACE_LOG(TRACE_YPARSER, "YParser error details: %v...", errObj)

	return  errObj
}

func FindNode(root *YParserNode, xpath string) *YParserNode {
	return  (*YParserNode)(C.lyd_find_node((*C.struct_lyd_node)(root), C.CString(xpath)))
}

func GetModelNs(module *YParserModule) (ns, prefix string) {
	return C.GoString(((*C.struct_lys_module)(module)).ns),
	 C.GoString(((*C.struct_lys_module)(module)).prefix)
}

//Get model details for child under list/choice/case
func getModelChildInfo(l *YParserListInfo, node *C.struct_lys_node,
	underWhen bool, whenExpr *WhenExpression) {

	for sChild := node.child; sChild != nil; sChild = sChild.next {
		switch sChild.nodetype {
		case C.LYS_LIST:
			nodeInnerList := (*C.struct_lys_node_list)(unsafe.Pointer(sChild))
			innerListkeys := (*[10]*C.struct_lys_node_leaf)(unsafe.Pointer(nodeInnerList.keys))
			for idx := 0; idx < int(nodeInnerList.keys_size); idx++ {
				keyName := C.GoString(innerListkeys[idx].name)
				l.MapLeaf = append(l.MapLeaf, keyName)
			}
		case C.LYS_USES:
			nodeUses := (*C.struct_lys_node_uses)(unsafe.Pointer(sChild))
			if (nodeUses.when != nil) {
				usesWhenExp := WhenExpression {
					Expr: C.GoString(nodeUses.when.cond),
				}
				listName := l.ListName + "_LIST"
				l.WhenExpr[listName] = append(l.WhenExpr[listName],
				&usesWhenExp)
				getModelChildInfo(l, sChild, true, &usesWhenExp)
			} else {
				getModelChildInfo(l, sChild, false, nil)
			}
		case C.LYS_CHOICE:
			nodeChoice := (*C.struct_lys_node_choice)(unsafe.Pointer(sChild))
			if (nodeChoice.when != nil) {
				chWhenExp := WhenExpression {
					Expr: C.GoString(nodeChoice.when.cond),
				}
				listName := l.ListName + "_LIST"
				l.WhenExpr[listName] = append(l.WhenExpr[listName],
				&chWhenExp)
				getModelChildInfo(l, sChild, true, &chWhenExp)
			} else {
				getModelChildInfo(l, sChild, false, nil)
			}
		case C.LYS_CASE:
			nodeCase := (*C.struct_lys_node_case)(unsafe.Pointer(sChild))
			if (nodeCase.when != nil) {
				csWhenExp := WhenExpression {
					Expr: C.GoString(nodeCase.when.cond),
				}
				listName := l.ListName + "_LIST"
				l.WhenExpr[listName] = append(l.WhenExpr[listName],
				&csWhenExp)
				getModelChildInfo(l, sChild, true, &csWhenExp)
			} else {
				if underWhen {
					getModelChildInfo(l, sChild, underWhen, whenExpr)
				} else {
					getModelChildInfo(l, sChild, false, nil)
				}
			}
		case C.LYS_LEAF, C.LYS_LEAFLIST:
			sleaf := (*C.struct_lys_node_leaf)(unsafe.Pointer(sChild))
			if sleaf == nil {
				continue
			}

			leafName := C.GoString(sleaf.name)

			if (sChild.nodetype == C.LYS_LEAF) {
				if (sleaf.dflt != nil) {
					l.DfltLeafVal[leafName] = C.GoString(sleaf.dflt)
				}
			} else {
				sLeafList := (*C.struct_lys_node_leaflist)(unsafe.Pointer(sChild))
				if (sleaf.dflt != nil) {
					//array of default values
					dfltValArr := (*[256]*C.char)(unsafe.Pointer(sLeafList.dflt))

					tmpValStr := ""
					for idx := 0; idx < int(sLeafList.dflt_size); idx++ {
						if (idx > 0) {
							//Separate multiple values by ,
							tmpValStr = tmpValStr + ","
						}

						tmpValStr = tmpValStr + C.GoString(dfltValArr[idx])
					}

					//Remove last ','
					l.DfltLeafVal[leafName] = tmpValStr
				}
			}

			//If parent has when expression,
			//just add leaf to when expression node list
			if underWhen {
				whenExpr.NodeNames = append(whenExpr.NodeNames, leafName)
			}

			//Check for leafref expression
			leafRefs := C.lys_get_leafrefs(sleaf)
			if (leafRefs != nil) {
				leafRefPaths := (*[10]*C.char)(unsafe.Pointer(&leafRefs.path))
				for idx := 0; idx < int(leafRefs.count); idx++ {
					l.LeafRef[leafName] = append(l.LeafRef[leafName],
					C.GoString(leafRefPaths[idx]))
				}
			}

			//Check for must expression; one must expession only per leaf
			if (sleaf.must_size > 0) {
				must := (*[20]C.struct_lys_restr)(unsafe.Pointer(sleaf.must))
				for  idx := 0; idx < int(sleaf.must_size); idx++ {
					exp := XpathExpression{Expr: C.GoString(must[idx].expr)}

					if (must[idx].eapptag != nil) {
						exp.ErrCode = C.GoString(must[idx].eapptag)
					}
					if (must[idx].emsg != nil) {
						exp.ErrStr = C.GoString(must[idx].emsg)
					}

					l.XpathExpr[leafName] = append(l.XpathExpr[leafName],
					&exp)
				}
			}

			//Check for when expression
			if (sleaf.when != nil) {
				l.WhenExpr[leafName] = append(l.WhenExpr[leafName],
				&WhenExpression {
					Expr: C.GoString(sleaf.when.cond),
					NodeNames: []string{leafName},
				})
			}

			//Check for custom extension
			if (sleaf.ext_size > 0) {
				exts := (*[10]*C.struct_lys_ext_instance)(unsafe.Pointer(sleaf.ext))
				for  idx := 0; idx < int(sleaf.ext_size); idx++ {
					if (C.GoString(exts[idx].def.name) == "custom-validation") {
						argVal := C.GoString(exts[idx].arg_value)
						if (argVal != "") {
							l.CustValidation[leafName] = append(l.CustValidation[leafName], argVal)
						}
					}
				}
			}

			// check for mandatory flag
			if (sChild.flags & C.LYS_MAND_MASK) == C.LYS_MAND_TRUE {
				l.MandatoryNodes[leafName] = true
			} else if (sChild.flags & C.LYS_MAND_MASK) == C.LYS_MAND_FALSE {
				l.MandatoryNodes[leafName] = false
			}
		}
	}
}

//GetModelListInfo Get model info for YANG list and its subtree
func GetModelListInfo(module *YParserModule) []*YParserListInfo {
	var list []*YParserListInfo

	mod := (*C.struct_lys_module)(module)
	set := C.lys_find_path(mod, nil,
	C.CString(fmt.Sprintf("/%s/*", C.GoString(mod.name))))

	if (set == nil) {
		return nil
	}

	for idx := 0; idx < int(set.number); idx++ { //for each container

		snode := C.lys_get_snode(set, C.int(idx))
		snodec := (*C.struct_lys_node_container)(unsafe.Pointer(snode))
		slist := (*C.struct_lys_node_list)(unsafe.Pointer(snodec.child))

		//for each list
		for ; slist != nil; slist = (*C.struct_lys_node_list)(unsafe.Pointer(slist.next)) {
			var l YParserListInfo
			listName :=  C.GoString(slist.name)
			l.RedisTableName = C.GoString(snodec.name)

			tableName := listName
			if (strings.HasSuffix(tableName, "_LIST")) {
				tableName = tableName[0:len(tableName) - len("_LIST")]
			}
			l.ListName = tableName
			l.ModelName = C.GoString(mod.name)
			//Default database is CONFIG_DB since CVL works with config db mainly
			l.Module = module
			l.DbName = "CONFIG_DB"
			//default delim '|'
			l.RedisKeyDelim = "|"
			//Default table size is -1 i.e. size limit
			l.RedisTableSize = -1
			if (slist.max  > 0) {
				l.RedisTableSize = int(slist.max)
			}

			l.LeafRef = make(map[string][]string)
			l.XpathExpr = make(map[string][]*XpathExpression)
			l.CustValidation = make(map[string][]string)
			l.WhenExpr = make(map[string][]*WhenExpression)
			l.DfltLeafVal = make(map[string]string)
			l.MandatoryNodes = make(map[string]bool)

			//Add keys
			keys := (*[10]*C.struct_lys_node_leaf)(unsafe.Pointer(slist.keys))
			for idx := 0; idx < int(slist.keys_size); idx++ {
				keyName := C.GoString(keys[idx].name)
				l.Keys = append(l.Keys, keyName)
			}

			//Check for must expression
			if (slist.must_size > 0) {
				must := (*[10]C.struct_lys_restr)(unsafe.Pointer(slist.must))
				for  idx := 0; idx < int(slist.must_size); idx++ {
					exp := XpathExpression{Expr: C.GoString(must[idx].expr)}
					if (must[idx].eapptag != nil) {
						exp.ErrCode = C.GoString(must[idx].eapptag)
					}
					if (must[idx].emsg != nil) {
						exp.ErrStr = C.GoString(must[idx].emsg)
					}

					l.XpathExpr[listName] = append(l.XpathExpr[listName],
					&exp)
				}
			}

			//Check for custom extension
			if (slist.ext_size > 0) {
				exts := (*[10]*C.struct_lys_ext_instance)(unsafe.Pointer(slist.ext))
				for  idx := 0; idx < int(slist.ext_size); idx++ {

					extName := C.GoString(exts[idx].def.name)
					argVal := C.GoString(exts[idx].arg_value)

					switch extName {
					case "custom-validation":
						if (argVal != "") {
							l.CustValidation[listName] = append(l.CustValidation[listName], argVal)
						}
					case "db-name":
						l.DbName = argVal
					case "key-delim":
						l.RedisKeyDelim = argVal
					case "key-pattern":
						l.RedisKeyPattern = argVal
					case "dependent-on":
						l.DependentOnTable = argVal
					}
				}

			}

			//Add default key pattern
			if l.RedisKeyPattern == "" {
				keyPattern := []string{tableName}
				for idx := 0; idx < len(l.Keys); idx++ {
					keyPattern = append(keyPattern, fmt.Sprintf("{%s}", l.Keys[idx]))
				}
				l.RedisKeyPattern = strings.Join(keyPattern, l.RedisKeyDelim)
			}

			getModelChildInfo(&l,
			(*C.struct_lys_node)(unsafe.Pointer(slist)), false, nil)

			list = append(list, &l)
		}//each list inside a container
	}//each container

	C.free(unsafe.Pointer(set))
	return list
}

