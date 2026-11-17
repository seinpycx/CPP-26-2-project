#include <iostream>
#include <fstream>
#include <string>

using namespace std;

const string SETTINGS_FILE = "diary_settings.txt";
const int MAX_ATTEMPTS = 5;

class LoginManager {
private:
    string loginPassword;
    int questionNumber = 0;
    string securityAnswer;
    string masterKey;

    // 영문 대소문자, 숫자, 기호만 포함되어 있는지 확인함
    bool containsOnlyAllowedCharacters(const string& text) const {
        for (string::size_type i = 0; i < text.length(); i++) {
            unsigned char ch = static_cast<unsigned char>(text[i]);

            bool isUppercase = (ch >= 'A' && ch <= 'Z');
            bool isLowercase = (ch >= 'a' && ch <= 'z');
            bool isDigit = (ch >= '0' && ch <= '9');
            bool isSymbol = (ch >= '!' && ch <= '/') ||
                            (ch >= ':' && ch <= '@') ||
                            (ch >= '[' && ch <= '`') ||
                            (ch >= '{' && ch <= '~');

            if (!isUppercase && !isLowercase && !isDigit && !isSymbol) {
                return false;
            }
        }
        return true;
    }

    bool isFourDigitMasterKey(const string& key) const {
        if (key.length() != 4) {
            return false;
        }

        for (string::size_type i = 0; i < key.length(); i++) {
            if (key[i] < '0' || key[i] > '9') {
                return false;
            }
        }

        return true;
    }

    string getSecurityQuestion() const {
        if (questionNumber == 1) return "가장 기억에 남는 선생님은?";
        if (questionNumber == 2) return "가장 기억에 남는 크리스마스 선물은?";
        if (questionNumber == 3) return "가장 좋아하는 메뉴는?";
        if (questionNumber == 4) return "먹지 못하는 음식은?";
        if (questionNumber == 5) return "가장 좋았던 여행 장소는?";
        return "";
    }

    // 로그인 비밀번호를 최대 5회 입력받아 확인함
    bool enterPassword(const string& prompt) const {
        string inputPassword;

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            cout << prompt;
            getline(cin, inputPassword);

            if (checkLoginPassword(inputPassword)) {
                cout << "비밀번호가 확인되었습니다.\n";
                return true;
            }

            cout << "비밀번호가 틀렸습니다. 남은 횟수: "
                 << MAX_ATTEMPTS - attempt << "회\n";
        }

        return false;
    }

    // 본인 확인 답변을 최대 5회 입력받아 확인함
    bool verifySecurityAnswer() const {
        string inputAnswer;

        cout << "\n본인 확인 질문: " << getSecurityQuestion() << "\n";

        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            cout << "답변을 입력하세요: ";
            getline(cin, inputAnswer);

            if (inputAnswer == securityAnswer) {
                cout << "본인 확인에 성공했습니다.\n";
                return true;
            }

            cout << "답변이 틀렸습니다. 남은 횟수: "
                 << MAX_ATTEMPTS - attempt << "회\n";
        }

        return false;
    }

public:
    // 설정 파일에서 비밀번호와 나머지 설정을 불러옴
    // 이전 버전의 비밀번호 한 줄 파일도 읽고 나머지 설정을 이어서 입력받음
    bool loadSettings() {
        ifstream inputFile(SETTINGS_FILE);

        if (!inputFile.is_open()) {
            return false;
        }

        if (!getline(inputFile, loginPassword) || loginPassword == "") {
            return false;
        }

        string savedQuestionNumber;
        if (getline(inputFile, savedQuestionNumber)) {
            if (savedQuestionNumber == "1") questionNumber = 1;
            else if (savedQuestionNumber == "2") questionNumber = 2;
            else if (savedQuestionNumber == "3") questionNumber = 3;
            else if (savedQuestionNumber == "4") questionNumber = 4;
            else if (savedQuestionNumber == "5") questionNumber = 5;

            getline(inputFile, securityAnswer);
            getline(inputFile, masterKey);
        }

        return true;
    }

    // 설정 파일에 로그인 비밀번호, 질문 번호, 답변, 마스터키를 저장함
    bool saveSettings() const {
        ofstream outputFile(SETTINGS_FILE);

        if (!outputFile.is_open()) {
            cout << "설정 파일을 열 수 없습니다.\n";
            return false;
        }

        outputFile << loginPassword << '\n';
        outputFile << questionNumber << '\n';
        outputFile << securityAnswer << '\n';
        outputFile << masterKey << '\n';

        if (!outputFile) {
            cout << "설정 정보를 파일에 저장하지 못했습니다.\n";
            return false;
        }

        return true;
    }

    bool setLoginPassword() {
        string password;
        string confirmPassword;

        cout << "\n[로그인 비밀번호 조건]\n";
        cout << "- 6자 이상\n";
        cout << "- 공백 불가\n";
        cout << "- 영문 대소문자, 숫자, 기호만 사용 가능\n\n";

        while (true) {
            cout << "로그인 비밀번호를 설정하세요: ";
            getline(cin, password);

            if (password == "") {
                cout << "비밀번호는 비워둘 수 없습니다. 다시 입력하세요.\n\n";
                continue;
            }

            if (password.length() < 6) {
                cout << "비밀번호는 6자 이상이어야 합니다. 다시 입력하세요.\n\n";
                continue;
            }

            if (!containsOnlyAllowedCharacters(password)) {
                cout << "영문 대소문자, 숫자, 기호만 사용할 수 있습니다. 공백과 한글은 입력할 수 없습니다.\n\n";
                continue;
            }

            cout << "비밀번호를 한 번 더 입력하세요: ";
            getline(cin, confirmPassword);

            if (password == confirmPassword) {
                loginPassword = password;
                cout << "로그인 비밀번호 설정이 완료되었습니다.\n";
                return true;
            }

            cout << "두 비밀번호가 일치하지 않습니다. 처음부터 다시 설정하세요.\n\n";
        }
    }

    bool setSecurityQuestionAndAnswer() {
        string choice;

        cout << "\n[본인 확인 질문 선택]\n";
        cout << "1. 가장 기억에 남는 선생님\n";
        cout << "2. 가장 기억에 남는 크리스마스 선물\n";
        cout << "3. 가장 좋아하는 메뉴\n";
        cout << "4. 먹지 못하는 음식\n";
        cout << "5. 가장 좋았던 여행 장소\n";

        while (true) {
            cout << "질문 번호를 선택하세요 (1~5): ";
            getline(cin, choice);

            if (choice == "1") questionNumber = 1;
            else if (choice == "2") questionNumber = 2;
            else if (choice == "3") questionNumber = 3;
            else if (choice == "4") questionNumber = 4;
            else if (choice == "5") questionNumber = 5;
            else {
                cout << "1부터 5까지의 번호를 입력하세요.\n";
                continue;
            }
            break;
        }

        while (true) {
            cout << getSecurityQuestion() << "\n답변을 설정하세요: ";
            getline(cin, securityAnswer);

            if (securityAnswer != "") {
                cout << "본인 확인 질문과 답변이 설정되었습니다.\n";
                return true;
            }
            cout << "답변은 비워둘 수 없습니다. 다시 입력하세요.\n";
        }
    }

    bool setMasterKey() {
        string key;
        string confirmKey;

        while (true) {
            cout << "\n잠긴 다이어리 복구에 사용할 숫자 4자리 마스터키를 설정하세요: ";
            getline(cin, key);

            if (!isFourDigitMasterKey(key)) {
                cout << "마스터키는 0~9 숫자 4자리로 입력하세요.\n";
                continue;
            }

            cout << "마스터키를 한 번 더 입력하세요: ";
            getline(cin, confirmKey);

            if (key == confirmKey) {
                masterKey = key;
                cout << "마스터키 설정이 완료되었습니다.\n";
                return true;
            }

            cout << "두 마스터키가 일치하지 않습니다. 다시 설정하세요.\n";
        }
    }

    bool setupMissingSettings() {
        if (loginPassword == "" && !setLoginPassword()) {
            return false;
        }

        if ((questionNumber < 1 || questionNumber > 5 || securityAnswer == "") &&
            !setSecurityQuestionAndAnswer()) {
            return false;
        }

        if (!isFourDigitMasterKey(masterKey) && !setMasterKey()) {
            return false;
        }

        return saveSettings();
    }

    bool checkLoginPassword(const string& input) const {
        return input == loginPassword;
    }

    // 비밀번호 5회 실패 시 본인 확인 후 비밀번호 재입력을 진행함
    bool login() const {
        cout << "\n=== 로그인 ===\n";

        if (enterPassword("로그인 비밀번호를 입력하세요: ")) {
            return true;
        }

        cout << "\n비밀번호 입력 5회 실패. 본인 확인을 진행합니다.\n";
        if (!verifySecurityAnswer()) {
            cout << "본인 확인 5회 실패로 다이어리 접근을 차단합니다.\n";
            return false;
        }

        cout << "본인 확인에 성공했습니다. 로그인 비밀번호 입력 기회를 다시 제공합니다.\n";
        if (!enterPassword("로그인 비밀번호를 다시 입력하세요: ")) {
            cout << "비밀번호 재입력 5회 실패로 다이어리 접근을 차단합니다.\n";
            return false;
        }

        return true;
    }
};

// 다이어리 항목 하나의 번호, 제목, 본문, 잠금 상태를 관리함
class DiaryEntry {
// private 영역은 클래스 외부에서 멤버 변수에 직접 접근하지 못하게 함
private:
    // 다이어리 항목을 구분하는 번호를 저장함
    int entryNumber;

    // 다이어리 제목을 저장함
    string title;

    // 다이어리 본문을 저장함
    string content;

    // 항목이 잠겨 있는지 저장하며 false는 일반 상태를 의미함
    bool locked;

// public 영역은 클래스 외부에서 사용할 수 있는 생성자와 멤버 함수를 제공함
public:
    // 항목 정보를 전달받아 멤버 변수를 초기화하고 처음 상태를 일반으로 설정함
    DiaryEntry(int number, const string& entryTitle, const string& entryContent)
        : entryNumber(number), title(entryTitle), content(entryContent), locked(false) {}

    // 다이어리 항목 번호를 외부에 반환함
    int getEntryNumber() const {
        return entryNumber;
    }

    // 다이어리 제목을 외부에 반환함
    string getTitle() const {
        return title;
    }

    // 다이어리 본문을 외부에 반환함
    string getContent() const {
        return content;
    }

    // 잠금 상태를 외부에 반환하며 true면 잠김, false면 일반 상태임
    bool isLocked() const {
        return locked;
    }
};

int main() {
    LoginManager loginManager;

    if (loginManager.loadSettings()) {
        cout << "저장된 설정을 불러왔습니다.\n";
    } else {
        cout << "=== 보안 다이어리 초기 설정 ===\n";
    }

    if (!loginManager.setupMissingSettings()) {
        return 1;
    }

    cout << "설정 파일에 저장했습니다: " << SETTINGS_FILE << "\n";

    if (loginManager.login()) {
        cout << "로그인에 성공했습니다.\n";
    } else {
        cout << "로그인할 수 없습니다. 프로그램을 종료합니다.\n";
    }

    return 0;
}
