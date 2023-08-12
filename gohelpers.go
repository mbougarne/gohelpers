/*
A helper utilities that I use in my work in Go and want to share with the community. It has helpers to work with `dotEnv` in a basic and simple use, and `JWT` to generate, and validate tokens and refresh tokens.
*/
package gohelpers

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Hash password with the bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Verify if two passwords matched with bcrypt
func VerifyHashedPassword(plain, hashed string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	return err == nil
}

// Convert a struct of any type to a map of keys of strings and values of any type.
func StructToMap(in any) map[string]any {
	reflectedStruct := reflect.ValueOf(in)
	fieldsLength := reflectedStruct.NumField()
	resultMap := make(map[string]interface{}, fieldsLength)

	for i := 0; i < fieldsLength; i++ {
		resultMap[strings.ToLower(reflectedStruct.Type().Field(i).Name)] = reflectedStruct.Field(i).Interface()
	}

	return resultMap
}

// Remove a field from struct of any type, and return a new map of keys of strings and values of any type.
func RemoveFieldFromStruct(in any, field string) (map[string]interface{}, error) {
	mapResult := make(map[string]interface{})
	tempMap := make(map[string]interface{})

	b, marshal_err := json.Marshal(&in)

	if marshal_err != nil {
		return nil, marshal_err
	}

	un_marshal_err := json.Unmarshal(b, &tempMap)

	if un_marshal_err != nil {
		return nil, un_marshal_err
	}

	for k, v := range tempMap {
		if k != field {
			mapResult[k] = v
		}
	}

	return mapResult, nil
}

// Check if a value of any type exist in a slice of any type
func InSlice(in interface{}, list interface{}) bool {
	switch t := list.(type) {
	case []string, []int, []float32, []float64, []byte, []bool, []rune:
		reflectedList := reflect.ValueOf(t)
		length := reflectedList.Len()

		for i := 0; i < length; i++ {
			if reflectedList.Index(i).Interface() == in {
				return true
			}
		}
	default:
		return false
	}

	return false
}

/*
Generate random string in md5 format
A good use of this func is to rename the uploaded files.
*/
func RandomMd5String(input string) string {
	ct := fmt.Sprint(time.Now().UTC().UnixMilli())
	input = ct + input
	hashedM5 := md5.Sum([]byte(input))

	return hex.EncodeToString(hashedM5[:])
}

/*
Convert slice of strings to map of strings. It will take the first item in the slice as a map key, and the next item as the map value.
*/
func SliceStringToMapString(slice []string) map[string]string {
	resultMap := make(map[string]string, len(slice))

	for i := 0; i < len(slice); i += 2 {
		resultMap[slice[i]] = slice[i+1]
	}

	return resultMap
}

/*
Convert slice of these types:
`[]string, []int, []float32, []float64, []byte, []bool, []rune`
To a `map[string]interface{}`. It will return an error if the type is not supported, or the map if there's no error.
*/
func SliceToMap(slice interface{}) (map[string]interface{}, error) {
	var resultMap map[string]interface{}

	switch t := slice.(type) {
	case []string, []int, []float32, []float64, []byte, []bool, []rune:
		reflectedList := reflect.ValueOf(t)
		length := reflectedList.Len()
		resultMap = make(map[string]interface{}, length)

		for i := 0; i < length; i += 2 {
			resultMap[strings.ToLower(reflectedList.Type().Field(i).Name)] = reflectedList.Field(i + 1).Interface()
		}

	default:
		return nil, fmt.Errorf("unsupported type")
	}

	return resultMap, nil
}

/*
Flatten a map
*/
func FlattenMap(in map[string]interface{}, want map[string]interface{}) {
	for k, v := range in {
		switch child := v.(type) {
		case map[string]interface{}:
			FlattenMap(child, want)
		case []interface{}:
			want = StructToMap(child)
		default:
			want[k] = v
		}
	}
}
