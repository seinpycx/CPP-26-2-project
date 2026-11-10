#include <iostream>
#include <fstream> // 비밀번호 설정을 파일에 저장하고 다음 실행 시 불러오기 위해 사용
#include <string>

using namespace std;

const string SETTINGS_FILE = "diary_settings.txt";

class LoginManager {
private:
    string loginPassword;

    // 영문 대소문자, 숫자, 기호만 포함되어 있는지 확인
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

public:
    // 저장된 로그인 비밀번호를 설정 파일에서 불러옴
    bool loadLoginPassword() {
        ifstream inputFile(SETTINGS_FILE);

        if (!inputFile.is_open()) {
            return false;
        }

        getline(inputFile, loginPassword);
        return loginPassword != "";
    }

    // 로그인 비밀번호를 설정 파일에 저장
    bool saveLoginPassword() const {
        ofstream outputFile(SETTINGS_FILE);

        if (!outputFile.is_open()) {
            cout << "설정 파일을 열 수 없습니다.\n";
            return false;
        }

        outputFile << loginPassword << '\n';

        if (!outputFile) {
            cout << "비밀번호를 파일에 저장하지 못했습니다.\n";
            return false;
        }

        return true;
    }

    // 처음 사용할 로그인 비밀번호를 설정한다.
    bool setLoginPassword() {
        string password;
        string confirmPassword;

        cout << "\n[비밀번호 설정 조건]\n";
        cout << "- 6자 이상\n";
        cout << "- 공백 불가\n";
        cout << "- 영문 대소문자, 숫자, 기호만 사용 가능 (공백·한글 불가)\n\n";

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
                cout << "영문 대소문자, 숫자, 기호만 사용할 수 있습니다. 공백과 한글은 입력할 수 없습니다. 다시 입력하세요.\n\n";
                continue;
            }

            cout << "비밀번호를 한 번 더 입력하세요: ";
            getline(cin, confirmPassword);

            if (password == confirmPassword) {
                loginPassword = password;

                if (!saveLoginPassword()) {
                    return false;
                }

                cout << "로그인 비밀번호 설정이 완료되었습니다.\n";
                return true;
            }

            cout << "두 비밀번호가 일치하지 않습니다. 처음부터 다시 설정하세요.\n\n";
        }
    }

    // 나중에 로그인 기능에서 입력값을 확인할 때 사용할 함수
    bool checkLoginPassword(const string& input) const {
        return input == loginPassword;
    }
};

int main() {
    LoginManager loginManager;

    if (loginManager.loadLoginPassword()) {
        cout << "저장된 로그인 비밀번호 설정을 불러왔습니다.\n";
        cout << "이후 단계에서 이 값으로 로그인 기능을 연결하면 됩니다.\n";
        return 0;
    }

    cout << "=== 보안 다이어리 초기 설정 ===\n";
    if (!loginManager.setLoginPassword()) {
        return 1;
    }

    cout << "\n설정이 완료되었습니다. 설정 파일: " << SETTINGS_FILE << '\n';
    return 0;
}
