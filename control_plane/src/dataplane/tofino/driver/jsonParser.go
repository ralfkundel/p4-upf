/*
# Copyright 2022-present Ralf Kundel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*/

package tofino

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
)

type Table struct {
	name    string
	id      int
	keys    []Key
	actions []Action
}

type PortTable struct {
	name  string
	id    int
	keys  []Key
	datas []Data
}

type Key struct {
	name       string
	id         int
	match_type string
}

type Action struct {
	name  string
	id    int
	datas []Data
}

type Data struct {
	name string
	id   int
}

func UnmarshalBfJson(jsonStr string) []Table {
	var bfjson map[string]interface{}
	var jsonTablesStruct []Table

	json.Unmarshal([]byte(jsonStr), &bfjson)
	tables := bfjson["tables"]
	if tables != nil {
		for _, table := range tables.([]interface{}) {
			switch table.(type) {
			case map[string]interface{}:
				name := table.(map[string]interface{})["name"]
				id := table.(map[string]interface{})["id"]
				// keys and actions will be added later to jsonTablesStruct
				jsonTablesStruct = append(jsonTablesStruct, Table{name: name.(string), id: int(id.(float64))})
				tbl := table.(map[string]interface{})

				var keysStruct []Key
				keys := tbl["key"]
				if keys != nil {
					for _, key := range keys.([]interface{}) {
						name := key.(map[string]interface{})["name"]
						id := key.(map[string]interface{})["id"]
						match_type := key.(map[string]interface{})["match_type"]
						keysStruct = append(keysStruct, Key{name: name.(string), id: int(id.(float64)), match_type: match_type.(string)})
					}
				}
				// use last element of jsonTablesStruct slice (which is our current element)
				jsonTablesStruct[len(jsonTablesStruct)-1].keys = keysStruct

				var actionsStruct []Action
				actions := tbl["action_specs"]
				if actions != nil {
					for _, action := range actions.([]interface{}) {
						name := action.(map[string]interface{})["name"]
						id := action.(map[string]interface{})["id"]
						datas := action.(map[string]interface{})["data"]
						var datasStruct []Data
						if datas != nil {
							for _, data := range datas.([]interface{}) {
								name := data.(map[string]interface{})["name"]
								id := data.(map[string]interface{})["id"]
								if name != nil && id != nil {
									datasStruct = append(datasStruct, Data{name: name.(string), id: int(id.(float64))})
								}
							}
						}
						actionsStruct = append(actionsStruct, Action{name: name.(string), id: int(id.(float64)), datas: datasStruct})
					}
					// use last element of jsonTablesStruct slice (which is our current element)
					jsonTablesStruct[len(jsonTablesStruct)-1].actions = actionsStruct
				}
			}
		}
	} else {
		log.Warning("BfruntimeInfo JSON parsing not possible")
	}

	return jsonTablesStruct
}

// non P4 json has no action entry => only key and data lists
func UnmarshalPortJson(jsonStr string) []PortTable {
	var bfjson map[string]interface{}
	var jsonTablesStruct []PortTable

	json.Unmarshal([]byte(jsonStr), &bfjson)
	tables := bfjson["tables"]

	if tables != nil {
		for _, table := range tables.([]interface{}) {
			switch table.(type) {
			case map[string]interface{}:
				name := table.(map[string]interface{})["name"]
				id := table.(map[string]interface{})["id"]
				if name.(string) == "$PORT" {
					// keys and actions will be added later to jsonTablesStruct
					jsonTablesStruct = append(jsonTablesStruct, PortTable{name: name.(string), id: int(id.(float64))})
					tbl := table.(map[string]interface{})

					var keysStruct []Key
					keys := tbl["key"]
					if keys != nil {
						for _, key := range keys.([]interface{}) {
							name := key.(map[string]interface{})["name"]
							id := key.(map[string]interface{})["id"]
							keysStruct = append(keysStruct, Key{name: name.(string), id: int(id.(float64))})
						}
					}
					// use last element of jsonTablesStruct slice (which is our current element)
					jsonTablesStruct[len(jsonTablesStruct)-1].keys = keysStruct

					var datasStruct []Data
					datas := tbl["data"]
					if datas != nil {
						for _, key := range datas.([]interface{}) {
							singleton := key.(map[string]interface{})["singleton"]
							name := singleton.(map[string]interface{})["name"]
							id := singleton.(map[string]interface{})["id"]

							//name := key.(map[string]interface {})["name"]
							//id := key.(map[string]interface {})["id"]
							datasStruct = append(datasStruct, Data{name: name.(string), id: int(id.(float64))})
						}
					}

					jsonTablesStruct[len(jsonTablesStruct)-1].datas = datasStruct
				}

			}
		}
	} else {
		log.Warning("BfruntimeInfo JSON parsing not possible")
	}

	return jsonTablesStruct
}
