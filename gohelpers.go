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
Convert slice of strings to map of strings. Takes items in pairs where slice[i] is the key
and slice[i+1] is the value.

Parameters:
- slice: input slice of strings
- onOddLength: behavior for odd-length slices:
  - "skip": skip last element (default)
  - "empty": use empty string as value
  - "panic": panic on odd length (original behavior)
*/
func SliceStringToMapString(slice []string, onOddLength ...string) map[string]string {
	behavior := "skip" // default
	if len(onOddLength) > 0 {
		behavior = onOddLength[0]
	}

	resultMap := make(map[string]string, len(slice)/2+1)

	for i := 0; i < len(slice); i += 2 {
		if i+1 >= len(slice) {
			switch behavior {
			case "empty":
				resultMap[slice[i]] = ""
			case "panic":
				panic(fmt.Sprintf("odd number of elements in slice (got %d)", len(slice)))
			case "skip":
				// default - do nothing
			}
			break
		}
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
