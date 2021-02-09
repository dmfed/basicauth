package auth

import (
	"io/ioutil"
	"regexp"
	"strings"
)

var (
	configKeyValueRe = regexp.MustCompile(`(\w+):(\w+)\b[\t| |\n]*`)
)

func loadUserSecretMapFromFile(filename string) (map[UserName]Secret, error) {
	configrows, err := readConfigFileToSliceString(filename)
	if err != nil {
		userMap := make(map[UserName]Secret)
		return userMap, err
	}
	userMap := parseStringSliceToUserMap(configrows)
	return userMap, nil
}

func readConfigFileToSliceString(filename string) ([]string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(data), "\n"), nil
}

func parseStringSliceToUserMap(configrows []string) map[UserName]Secret {
	userMap := make(map[UserName]Secret)
	for _, row := range configrows {
		/* if strings.HasPrefix(row, "#") {
			continue
		}
		row = strings.Trim(row, " \n") */
		if configKeyValueRe.MatchString(row) {
			kvpair := configKeyValueRe.FindStringSubmatch(row)
			username := UserName(kvpair[1])
			secret := Secret(kvpair[2])
			userMap[username] = secret
		}
	}
	return userMap
}

func writeUserSecretMapToFile(filename string, userMap map[UserName]Secret) error {
	bytes, _ := convertUserSecretsMapToByteSlice(userMap)
	return ioutil.WriteFile(filename, bytes, 0644)
}

func convertUserSecretsMapToByteSlice(userMap map[UserName]Secret) ([]byte, error) {
	output := ""
	for user, secret := range userMap {
		output += string(user) + ":" + string(secret) + "\n"
	}
	return []byte(output), nil
}
