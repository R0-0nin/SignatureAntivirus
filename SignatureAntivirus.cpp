
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <string>

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

    std::cout << std::endl;

    if (virusesInfo.size() == 0) {

        std::cout << "< - - - - Y O U R  F I L E  I S  S A F E - - - - >" << std::endl;
        return;

    }

    std::cout << "< - - - - W A R N I N G - - - - >\n\nAntivirus found the signatures of viruses:\n" << std::endl;


    for (auto virusInfo : virusesInfo) {

        std::cout << "-------------------------------------\n\tVirus type: " << virusInfo.first << "\n\tVirus chance: " << virusInfo.second * 100 << "%" << std::endl;

    }

}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Send a file to check!" << std::endl; // arg check
        return 1;
    }

    std::string fileAddress{ argv[1] };
    std::vector<std::pair<std::string, float>> viruses{};

    for (unsigned i{ 1 }; i < 4; i++) {

        std::ifstream rules("AntivirusSignatures/open-threat-database-master/ruleset/rule_set" + std::to_string(i) + ".json"); // current rules
        //std::ifstream rules("AntivirusSignatures/open-threat-database-master/ruleset/rule_set1.json");
        Json::Reader reader;
        Json::Value jsonDb;   // starts as "null"; will contain the root value after parsing
        reader.parse(rules, jsonDb);
        rules.close();

        std::pair<std::string, float> virusInfo;
        std::string virusName{};


        for (unsigned j{ 0 }; j < jsonDb["files"].size(); j++) {

            virusInfo = sigChecker(jsonDb["files"][j].asString(), fileAddress);
            if(virusInfo.second > 0.5)
                viruses.emplace_back(virusInfo);

        }

    }

    antivirusPrinter(viruses);

}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
