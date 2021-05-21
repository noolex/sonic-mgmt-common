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

package cvl

import (
	"github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	"github.com/go-redis/redis/v7"
)

//Redis server side script
func loadLuaScript(luaScripts map[string]*redis.Script) {

	// Find entry which has given fieldName and value
	luaScripts["find_key"] = redis.NewScript(`
	local tableName=ARGV[1]
	local sep=ARGV[2]
	local keySetNames = {}
	ARGV[3]:gsub("([^|]+)",function(c) table.insert(keySetNames, c) end)
	local fieldName=ARGV[4]
	local fieldValue=ARGV[5]

	local entries = {}

	-- Check if field value is part of key
	if (#keySetNames == 1) then
		-- field is only key
		entries=redis.call('KEYS', tableName..sep..fieldValue)
	elseif (keySetNames[#keySetNames] == fieldName) then
		-- field is the last key
		entries=redis.call('KEYS', tableName..sep.."*"..sep..fieldValue)
	else
		-- field is not the last key
		entries=redis.call('KEYS', tableName.."*"..sep..fieldValue..sep.."*")
	end

	if (entries[1] ~= nil)
	then
		return entries[1]
	else

	-- Search through all keys for fieldName and fieldValue
		local entries=redis.call('KEYS', tableName..sep.."*")

		local idx = 1
		while(entries[idx] ~= nil)
		do
			local val = redis.call("HGET", entries[idx], fieldName)
            local valArrFld = redis.call("HGET", entries[idx], fieldName.."@")
            if ((val == fieldValue) or (valArrFld == fieldValue))
			then
				-- Return the key
				return entries[idx]
			end

			idx = idx + 1
		end
	end

	-- Could not find the key
	return ""
	`)

	//Find current number of entries in a table
	luaScripts["count_entries"] = redis.NewScript(`
	--ARGV[1] => Key patterns
	--ARGV[2] => Key names separated by '|'
	--ARGV[3] => predicate patterns
	--ARGV[4] => Field

	if (#ARGV == 1) then
		--count of all table entries
		return #redis.call('KEYS', ARGV[1])
	end

	-- count with filter
	local keys = redis.call('KEYS', ARGV[1])
	if #keys == 0 then return 0 end

	local cnt = 0

	local sepStart = string.find(keys[1], "|")
	if sepStart == nil then return ; end

	-- Function to load lua predicate code
	local function loadPredicateScript(str)
		if (str == nil or str == "") then return nil; end

		local f, err = loadstring("return function (k,h) " .. str .. " end")
		if f then return f(); else return nil;end
	end

	local keySetNames = {}
	ARGV[2]:gsub("([^|]+)",function(c) table.insert(keySetNames, c) end)

	local predicate = loadPredicateScript(ARGV[3])

	local field = ""
	if (ARGV[4] ~= nil) then field = ARGV[4]; end

	for _, key in ipairs(keys) do
		local hash = redis.call('HGETALL', key)
		local row = {}; local keySet = {}; local keyVal = {}
		local keyOnly = string.sub(key, sepStart+1)

		for index = 1, #hash, 2 do
			row[hash[index]] = hash[index + 1]
		end

		local incFlag = false
		if (predicate == nil) then
			incFlag = true
		else
			--Split key values
			keyOnly:gsub("([^|]+)", function(c)  table.insert(keyVal, c) end)

			for idx = 1, #keySetNames, 1 do
				keySet[keySetNames[idx]] = keyVal[idx]
			end

			if (predicate(keySet, row) == true) then
				incFlag = true
			end
		end

		if (incFlag == true) then
			if (field ~= "") then
				if (row[field] ~= nil) then
					cnt = cnt + 1 
				elseif (row[field.."@"] ~= nil) then
					row[field.."@"]:gsub("([^,]+)", function(c) cnt = cnt + 1 end)
				elseif (string.match(ARGV[2], field.."[|]?") ~= nil) then
					cnt = cnt + 1 
				end
			else
				cnt = cnt + 1
			end
		end
	end

	return cnt
	`)

	// Find entry which has given fieldName and value
	luaScripts["filter_keys"] = redis.NewScript(`
	--ARGV[1] => Key patterns
	--ARGV[2] => Key names separated by '|'
	--ARGV[3] => predicate patterns
	local filterKeys = ""

	local keys = redis.call('KEYS', ARGV[1])
	if #keys == 0 then return end

	local sepStart = string.find(keys[1], "|")
	if sepStart == nil then return ; end

	-- Function to load lua predicate code
	local function loadPredicateScript(str)
	if (str == nil or str == "") then return nil; end

	local f, err = loadstring("return function (k,h) " .. str .. " end")
	if f then return f(); else return nil;end
	end

	local keySetNames = {}
	ARGV[2]:gsub("([^|]+)",function(c) table.insert(keySetNames, c) end)

	local predicate = loadPredicateScript(ARGV[3])

	for _, key in ipairs(keys) do
		local hash = redis.call('HGETALL', key)
		local row = {}; local keySet = {}; local keyVal = {}
		local keyOnly = string.sub(key, sepStart+1)

		for index = 1, #hash, 2 do
			row[hash[index]] = hash[index + 1]
		end

		--Split key values
		keyOnly:gsub("([^|]+)", function(c)  table.insert(keyVal, c) end)

		for idx = 1, #keySetNames, 1 do
			keySet[keySetNames[idx]] = keyVal[idx]
		end

		if (predicate == nil) or (predicate(keySet, row) == true) then 
			filterKeys = filterKeys .. key .. ","
		end

	end

	return string.sub(filterKeys, 1, #filterKeys - 1)
	`)

	//Get filtered entries as per given key filters and predicate
	luaScripts["filter_entries"] = util.FILTER_ENTRIES_LUASCRIPT
}
