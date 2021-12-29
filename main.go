package openpaygops

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/dchest/siphash"
)

const (
	MAX_BASE             = 999
	MAX_ACTIVATION_VALUE = 995
	PAYG_DISABLE_VALUE   = 998
	COUNTER_SYNC_VALUE   = 999
	TOKEN_VALUE_OFFSET   = 1000
	TOKEN_TYPE_SET_TIME  = 1
	TOKEN_TYPE_ADD_TIME  = 2
)

type OpenPaygo struct {
	MaxBase                  int
	MaxActivationValue       int
	TokenValueOffsetExtended int
}

//OpenPaygoAPI :
type OpenPaygoAPI struct {
}

//NewOpenPaygoAPI : Init API
func NewOpenPaygoAPI() (OpenPaygoAPI, error) {
	return OpenPaygoAPI{}, nil
}

//GenerateTokenResponse :
type GenerateTokenResponse struct {
	Message string `json:"message"`
	Token   int    `json:"token"`
}

func (api *OpenPaygoAPI) UnlockProduct(starting_code int, privatekey string, device_last_count int) (GenerateTokenResponse, error) {

	days_to_activate := PAYG_DISABLE_VALUE //#* time_granularity#
	device_key_hex_binay, _ := hex.DecodeString(privatekey)
	mode := 0 //0 disable || 1 set || 2 add
	token := generate_standard_token(
		starting_code,
		device_key_hex_binay,
		days_to_activate,
		device_last_count,
		true,
		mode)
	return GenerateTokenResponse{Token: token}, nil
}

func (api *OpenPaygoAPI) GenerateDayToken(starting_code int, privatekey string, days int, device_last_count int, mode string) (GenerateTokenResponse, error) {
	//time_granularity := 1 //4
	//device_last_count := 1
	days_to_activate := days //#* time_granularity#
	if days_to_activate > MAX_ACTIVATION_VALUE {
		return GenerateTokenResponse{}, fmt.Errorf("TOO_MANY_DAYS_TO_ACTIVATE")
	}
	if len(fmt.Sprintf("%v", starting_code)) < 5 || privatekey == "" {
		return GenerateTokenResponse{}, fmt.Errorf("DEVICE INFO MISSING")
	}
	device_key_hex_binay, _ := hex.DecodeString(privatekey)
	modeAction := 1 //1 set - 2 add
	if mode == "add_time" {
		modeAction = 2
	} else if mode == "set_time" {
		modeAction = 1
	} else {
		return GenerateTokenResponse{}, fmt.Errorf("NO MODE FIND")
	}

	token := generate_standard_token(
		starting_code,
		device_key_hex_binay,
		days_to_activate,
		device_last_count,
		false,
		modeAction)
	return GenerateTokenResponse{Token: token}, nil
}

func generate_standard_token(starting_code int, key []byte, value, count int, restricted_digit_set bool, mode int) int {

	starting_code_base := get_token_base(starting_code)
	//log.Println("starting_code_base", starting_code_base)
	token_base := encode_base(starting_code_base, value)
	//log.Println("token_base", token_base)
	current_token, _ := put_base_in_token(starting_code, token_base)
	//log.Println("current_token", current_token)
	current_count_odd := count % 2
	//log.Println("current_count_odd", current_count_odd)
	new_count := 0
	if mode == TOKEN_TYPE_SET_TIME {
		//log.Println("mode", mode)
		if testEven(current_count_odd) { // Odd numbers are for Set Time
			new_count = count + 2
		} else {
			new_count = count + 1
		}
	} else {
		if testEven(current_count_odd) { // Even numbers are for Add Time
			new_count = count + 1
		} else {
			new_count = count + 2
		}
	}
	//log.Println("new_count", new_count)

	for i := 0; i < new_count; i++ {
		current_token = generate_next_token(current_token, key)
	}
	//log.Println("FINAL current_token", current_token)
	current_token, _ = put_base_in_token(current_token, token_base)
	//log.Println("FINAL current_token", current_token)
	if restricted_digit_set {
		log.Println("DO NOT WORK")
	}
	return current_token
}

func encode_base(base, number int) int {
	if number+base > 999 {
		return number + base - 1000
	}
	return number + base
}

func get_token_base(token int) int {
	return int(token % TOKEN_VALUE_OFFSET)
}
func put_base_in_token(token, token_base int) (int, error) {
	if token_base > MAX_BASE {
		return 0, fmt.Errorf("INVALID_VALUE")
	}
	return token - get_token_base(token) + token_base, nil
}

func generate_next_token(last_code int, key []byte) int {
	//log.Println("generate_next_token  last_code", last_code)
	conformed_token, _ := pack(">L", last_code)
	//log.Println("generate_next_token conformed_token", conformed_token)
	//log.Println("generate_next_token conformed_token", strconv.FormatInt(int64(binary.BigEndian.Uint64(conformed_token)), 16))
	conformed_token = append(conformed_token[0:4], conformed_token[0:4]...)
	//log.Println("generate_next_token conformed_token", conformed_token)
	//log.Println("generate_next_token conformed_token", strconv.FormatInt(int64(binary.BigEndian.Uint64(conformed_token)), 16))
	h := siphash.New(key)
	h.Write(conformed_token)
	token_hash := h.Sum64()
	//log.Println("token_hash", token_hash, " with ", fmt.Sprintf("%x", key))
	//log.Println("generate_next_token token_hash", token_hash)
	new_token := convert_hash_to_token(int(token_hash))
	//log.Println("generate_next_token new_token", new_token)
	return new_token
}

func pack(format string, value int) ([]byte, error) {
	bs := make([]byte, 8)

	switch format {
	case ">L":
		binary.BigEndian.PutUint32(bs, uint32(value))
		//fmt.Printf("%#v\n", bs)
		//fmt.Printf("%#b\n", bs)

		//NOT USED
		// i := binary.BigEndian.Uint64(bs)
		// fmt.Println(i)
	case ">Q":
		binary.BigEndian.PutUint64(bs, uint64(value))
		//fmt.Printf("%#v\n", bs)
		//fmt.Printf("%#b\n", bs)

	}
	return bs, nil
}

func convert_hash_to_token(token_hash int) int {
	//log.Println("convert_hash_to_token token_hash", token_hash)
	hash_int, _ := pack(">Q", token_hash)
	//log.Println("convert_hash_to_token hash_int", hash_int)
	hi_hash := int64(binary.BigEndian.Uint32(hash_int[0:4]))
	//log.Println("convert_hash_to_token hash_int", hi_hash)
	lo_hash := int64(binary.BigEndian.Uint32(hash_int[4:8]))
	//log.Println("convert_hash_to_token lo_hash", lo_hash)
	result_hash := hi_hash ^ lo_hash
	//log.Println("convert_hash_to_token result_hash", result_hash, " from ", hi_hash, " >> ", lo_hash)

	return convert_to_29_5_bits(int(result_hash))
}

func convert_to_29_5_bits(token_hash int) int {
	mask := ((1 << (32 - 2 + 1)) - 1) << 2
	temp := (token_hash & mask) >> 2
	if temp > 999999999 {
		temp = temp - 73741825
	}
	return temp
}

func convert_to_4_digit_token(token int) int {
	// restricted_digit_token = 0
	// bit_array = bit_array_from_int(source, 30)
	// for i in range(15):
	// 	this_array = bit_array[i*2:(i*2)+2]
	// 	restricted_digit_token += str(cls._bit_array_to_int(this_array)+1)
	// return int(restricted_digit_token)
	return 0
}

// func bit_array_from_int(source, bits) int {
// 	// bit_array = []
// 	// for i in range(bits):
// 	// 	bit_array += [bool(source & (1 << (bits - 1 - i)))]
// 	// return bit_array
// 	return 0
// }
