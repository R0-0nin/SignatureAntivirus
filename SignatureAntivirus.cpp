
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <string>

class SignatureAntivirus {

public:
    void stringToLower(std::string string) {

        for (unsigned i{}; i < string.length(); i++)
            string[i] = tolower(string[i]);

    }

    size_t maxCommonSubstringLength(const std::string& str1, const std::string& str2) {
        size_t maxLength = 0;
        size_t len1 = str1.length();
        size_t len2 = str2.length();

        // All substrings
        std::vector<std::vector<size_t>> dp(len1 + 1, std::vector<size_t>(len2 + 1, 0));

        for (size_t i = 1; i <= len1; ++i) {
            for (size_t j = 1; j <= len2; ++j) {
                if (str1[i - 1] == str2[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                    maxLength = std::max(maxLength, dp[i][j]);
                }
            }
        }

        return maxLength;
    }

    float equalityCheck(std::string fileContent, std::string signature) {

        stringToLower(fileContent);
        stringToLower(signature);

        size_t maxLength = maxCommonSubstringLength(fileContent, signature);

        return (static_cast<float>(maxLength) / signature.length());
    }

    std::pair<std::string, float> sigChecker(std::string signatureAddress, std::string fileToCheckAddress) {

        Json::Value sigValue;
        Json::Reader sigReader;

        std::ifstream fileToCheck(fileToCheckAddress);
        std::ifstream signature("AntivirusSignatures/open-threat-database-master/threat_db/" + signatureAddress);
        sigReader.parse(signature, sigValue);
        std::string virusSig{ sigValue["tlsh"].asString() };

        std::cout << typeid(virusSig).name() << std::endl;

        std::string fileString{};
        float previousStrChance{ 0.0 };
        float currentStrChance{ 0.0 };
        float totalVirusChance{ 0.0 };


        while (std::getline(fileToCheck, fileString)) {

            currentStrChance = equalityCheck(fileString, virusSig);
            if (previousStrChance + currentStrChance > 0.5 && previousStrChance + currentStrChance > totalVirusChance)
                totalVirusChance = previousStrChance + currentStrChance;

        }

        return std::pair<std::string, float>{sigValue["name"].asString(), totalVirusChance};

    }

    void antivirusPrinter(std::vector<std::pair<std::string, float>> virusesInfo) {

        if (virusesInfo.size() == 0) {

            std::cout << "File is safe!" << std::endl;
            return;

        }

        std::cout << "< - - - - W A R N I N G - - - - >\n\tAntivirus found the signatures of viruses:\n" << std::endl;


        for (auto virusInfo : virusesInfo) {

            std::cout << "-------------------------------------\n\tVirus name: " << virusInfo.first << "\n\tVirus chance: " << virusInfo.second << std::endl;

        }

    }

};


int main(int argc, char* argv[]) {

    SignatureAntivirus myAntivirus{};
    if (argc < 2) {
        std::cerr << "Send a file to check!" << std::endl; // arg check
        return 1;
    }

    std::string fileAddress{ argv[1] };
    std::vector<std::pair<std::string, float>> viruses{};

    for (unsigned i{ 1 }; i < 4; i++) {

        std::ifstream rules("AntivirusSignatures/open-threat-database-master/ruleset/rule_set" + std::to_string(i) + ".json"); // current rules

        Json::Reader reader;
        Json::Value jsonDb;   // starts as "null"; will contain the root value after parsing
        reader.parse(rules, jsonDb);
        rules.close();

        std::pair<std::string, float> virusInfo;
        std::string virusName{};


        std::cout << typeid(jsonDb["files"][0]).name() << std::endl;


        for (unsigned j{ 0 }; j < sizeof(jsonDb["files"]) / sizeof(jsonDb["files"][0]); j++) {

            virusInfo = myAntivirus.sigChecker(jsonDb["files"][j].asString(), fileAddress);
            viruses.emplace_back(virusInfo);

        }

    }

    myAntivirus.antivirusPrinter(viruses);

}
