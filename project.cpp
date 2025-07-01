#include <iostream>
#include <string>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cstdlib>
using namespace std;

// Reset
#define RESET   "\033[0m"

// Regular Colors
#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

// Dark (Normal) Backgrounds
#define BG_DARK_RED      "\033[41m"
#define BG_DARK_GREEN    "\033[42m"
#define BG_DARK_YELLOW   "\033[43m"
#define BG_DARK_BLUE     "\033[44m"

// Light (Bright) Backgrounds
#define BG_LIGHT_RED     "\033[101m"  // Bright Red BG
#define BG_LIGHT_GREEN   "\033[102m"  // Bright Green BG
#define BG_LIGHT_YELLOW  "\033[103m"  // Bright Yellow BG
#define BG_LIGHT_BLUE    "\033[104m"  // Bright Blue BG
// Custom exception class for file system errors
class FileSystemException : public exception
{
private:
    string message;
public:
    FileSystemException(const string& msg) : message(msg) {}
    const char* what() const noexcept override
    {
        return message.c_str();
    }
};

// Permission definitions
enum Permission
{
    PERM_READ = 0x1,
    PERM_WRITE = 0x2,
    PERM_EXECUTE = 0x4,
    PERM_MODIFY_ACCESS = 0x8
};

// Forward declarations
class User;
class FileMetadata;
class AVLTreeNode;

// Logged-in user tracking node
struct LoggedInUserNode {
    User* user;
    LoggedInUserNode* next;
    LoggedInUserNode(User* u) : user(u), next(NULL) {}
};

// Stack implementation without exception handling
template <typename T>
class Stack {
private:
    struct Node {
        T data;
        Node* next;
        Node(T val) : data(val), next(NULL) {}
    };
    Node* top;

public:
    Stack() : top(NULL) {}

    ~Stack() {
        while (!isEmpty()) {
            pop();
        }
    }

    void push(T val) {
        Node* newNode = new Node(val);
        newNode->next = top;
        top = newNode;
    }

    T pop() {
        if (!top) {
            cerr << "Error: Stack empty" << endl;
            return T();
        }
        Node* temp = top;
        T data = temp->data;
        top = top->next;
        delete temp;
        return data;
    }

    bool isEmpty() {
        return top == NULL;
    }
};

// Queue implementation with copy constructor
template <typename T>
class Queue {
private:
    struct Node {
        T data;
        Node* next;
        Node(T val) : data(val), next(NULL) {}
    };
    Node* front, * rear;
    int count;

public:
    Queue() : front(NULL), rear(NULL), count(0) {}

    // Copy constructor
    Queue(const Queue& other) : front(NULL), rear(NULL), count(0) {
        Node* current = other.front;
        while (current) {
            enqueue(current->data);
            current = current->next;
        }
    }

    ~Queue() {
        while (!isEmpty()) {
            dequeue();
        }
    }

    void enqueue(T val) {
        Node* newNode = new Node(val);
        if (!rear) {
            front = rear = newNode;
        }
        else {
            rear->next = newNode;
            rear = newNode;
        }
        count++;
    }

    T dequeue() {
        if (!front) {
            cerr << "Error: Queue empty" << endl;
            return T();
        }
        Node* temp = front;
        T data = front->data;
        front = front->next;
        if (!front) {
            rear = NULL;
        }
        delete temp;
        count--;
        return data;
    }

    bool isEmpty() {
        return front == NULL;
    }

    int size() const {
        return count;
    }
};

// Hash table implementation
template <typename K, typename V>
class HashTable {
private:
    struct Entry {
        K key;
        V value;
        Entry* next;
        Entry(K k, V v) : key(k), value(v), next(NULL) {}
    };
    static const int TABLE_SIZE = 128;
    Entry** table;

    int hash(K key) {
        unsigned long hash = 5381;
        for (size_t i = 0; i < key.length(); i++) {
            hash = ((hash << 5) + hash) + key[i];
        }
        return hash % TABLE_SIZE;
    }

public:
    HashTable() {
        table = new Entry * [TABLE_SIZE]();
    }

    ~HashTable() {
        for (int i = 0; i < TABLE_SIZE; i++) {
            Entry* entry = table[i];
            while (entry) {
                Entry* temp = entry;
                entry = entry->next;
                delete temp;
            }
        }
        delete[] table;
    }

    void insert(K key, V value) {
        int index = hash(key);
        Entry* entry = table[index];
        if (!entry) {
            table[index] = new Entry(key, value);
            return;
        }
        Entry* prev = NULL;
        while (entry) {
            if (entry->key == key) {
                entry->value = value;
                return;
            }
            prev = entry;
            entry = entry->next;
        }
        prev->next = new Entry(key, value);
    }

    bool get(K key, V& value) {
        int index = hash(key);
        Entry* entry = table[index];
        while (entry) {
            if (entry->key == key) {
                value = entry->value;
                return true;
            }
            entry = entry->next;
        }
        return false;
    }

    void remove(K key) {
        int index = hash(key);
        Entry* entry = table[index];
        Entry* prev = NULL;
        while (entry) {
            if (entry->key == key) {
                if (prev) {
                    prev->next = entry->next;
                }
                else {
                    table[index] = entry->next;
                }
                delete entry;
                return;
            }
            prev = entry;
            entry = entry->next;
        }
    }

    void iterate(void (*callback)(const K&, const V)) {
        for (int i = 0; i < TABLE_SIZE; i++) {
            Entry* entry = table[i];
            while (entry) {
                callback(entry->key, entry->value);
                entry = entry->next;
            }
        }
    }
};

// Compression implementation
class Compressor {
public:
    static string compressRLE(const string& input) {
        string output;
        int count = 1;
        for (size_t i = 1; i <= input.size(); i++) {
            if (i < input.size() && input[i] == input[i - 1]) {
                count++;
            }
            else {
                output += to_string(count) + input[i - 1];
                count = 1;
            }
        }
        return output;
    }

    static string decompressRLE(const string& input) {
        string output;
        int i = 0;
        while (i < input.size()) {
            string numStr;
            while (i < input.size() && isdigit(input[i])) {
                numStr += input[i++];
            }
            if (i >= input.size()) break;

            int count = numStr.empty() ? 1 : stoi(numStr);
            output += string(count, input[i++]);
        }
        return output;
    }

    static string compressDict(const string& input) {
        string output = input;
        size_t pos;
        while ((pos = output.find("the")) != string::npos) {
            output.replace(pos, 3, "1");
        }
        while ((pos = output.find("and")) != string::npos) {
            output.replace(pos, 3, "2");
        }
        return output;
    }

    static string decompressDict(const string& input) {
        string output = input;
        size_t pos;
        while ((pos = output.find("1")) != string::npos) {
            output.replace(pos, 1, "the");
        }
        while ((pos = output.find("2")) != string::npos) {
            output.replace(pos, 1, "and");
        }
        return output;
    }
};

// File version node
struct FileVersion {
    string content;
    time_t timestamp;
    FileVersion* prev;
    FileVersion* next;
    bool compressed;
    string compressionType;

    FileVersion(string c, time_t t) :
        content(c), timestamp(t), prev(NULL), next(NULL),
        compressed(false), compressionType("") {
    }
};

// File metadata with enhanced tracking
class FileMetadata {
public:
    string name;
    string type;
    size_t size;
    string owner;
    FileVersion* versions;
    time_t lastAccessed;
    int accessCount;

    FileMetadata(string n, string t, string o) :
        name(n), type(t), owner(o), versions(NULL),
        lastAccessed(time(NULL)), accessCount(0) {
        addVersion("");
    }

    ~FileMetadata() {
        FileVersion* current = versions;
        while (current) {
            FileVersion* temp = current;
            current = current->prev;
            delete temp;
        }
    }

    void addVersion(string content) {
        FileVersion* newVersion = new FileVersion(content, time(NULL));
        if (!versions) {
            versions = newVersion;
        }
        else {
            newVersion->prev = versions;
            versions->next = newVersion;
            versions = newVersion;
        }
        lastAccessed = time(NULL);
        accessCount++;
        size = content.size();
    }

    void compress(const string& method = "RLE") {
        if (versions) {
            if (method == "RLE") {
                versions->content = Compressor::compressRLE(versions->content);
            }
            else {
                versions->content = Compressor::compressDict(versions->content);
            }
            versions->compressed = true;
            versions->compressionType = method;
            size = versions->content.size();
        }
    }

    void decompress() {
        if (versions && versions->compressed) {
            if (versions->compressionType == "RLE") {
                versions->content = Compressor::decompressRLE(versions->content);
            }
            else {
                versions->content = Compressor::decompressDict(versions->content);
            }
            versions->compressed = false;
            size = versions->content.size();
        }
    }
};

// AVL Tree Node for optimized directory structure
class AVLTreeNode {
public:
    string name;
    bool isDirectory;
    AVLTreeNode* parent;
    AVLTreeNode* left;
    AVLTreeNode* right;
    HashTable<string, FileMetadata*> files;
    int height;

    AVLTreeNode(string n, bool dir, AVLTreeNode* p = NULL) :
        name(n), isDirectory(dir), parent(p), left(NULL), right(NULL), height(1) {
    }

    ~AVLTreeNode() {
        delete left;
        delete right;
    }

    int getBalance() {
        int leftHeight = left ? left->height : 0;
        int rightHeight = right ? right->height : 0;
        return leftHeight - rightHeight;
    }

    void updateHeight() {
        int leftHeight = left ? left->height : 0;
        int rightHeight = right ? right->height : 0;
        height = 1 + max(leftHeight, rightHeight);
    }

    AVLTreeNode* rotateRight() {
        AVLTreeNode* newRoot = left;
        left = newRoot->right;
        newRoot->right = this;

        if (left) left->parent = this;
        newRoot->parent = parent;
        parent = newRoot;

        updateHeight();
        newRoot->updateHeight();

        return newRoot;
    }

    AVLTreeNode* rotateLeft() {
        AVLTreeNode* newRoot = right;
        right = newRoot->left;
        newRoot->left = this;

        if (right) right->parent = this;
        newRoot->parent = parent;
        parent = newRoot;

        updateHeight();
        newRoot->updateHeight();

        return newRoot;
    }

    AVLTreeNode* balance() {
        updateHeight();
        int balance = getBalance();

        // Left heavy
        if (balance > 1) {
            if (left->getBalance() < 0) {
                left = left->rotateLeft();
            }
            return rotateRight();
        }

        // Right heavy
        if (balance < -1) {
            if (right->getBalance() > 0) {
                right = right->rotateRight();
            }
            return rotateLeft();
        }

        return this;
    }

    AVLTreeNode* insert(AVLTreeNode* node) {
        if (node->name < name) {
            left = left ? left->insert(node) : node;
            left->parent = this;
        }
        else {
            right = right ? right->insert(node) : node;
            right->parent = this;
        }
        return balance();
    }

    AVLTreeNode* find(const string& childName)
    {
        if (childName == name)
        {
            return this;
        }
        else if (childName < name)
        {
            return left ? left->find(childName) : NULL;
        }
        else {
            return right ? right->find(childName) : NULL;
        }
    }
};

// Cloud synchronization task
class SyncTask {
public:
    string filePath;
    string action; // "upload", "download", "delete"
    time_t timestamp;

    SyncTask(const string& path, const string& act)
        : filePath(path), action(act), timestamp(time(NULL)) {
    }
};

// Cloud synchronization manager
class CloudSync {
    Queue<SyncTask*> syncQueue;
    bool online;
    thread* syncThread;
    bool running;

public:
    CloudSync() : online(false), running(false), syncThread(NULL) {}

    ~CloudSync() {
        stopSync();
    }

    void startSync() {
        running = true;
        syncThread = new thread(&CloudSync::syncLoop, this);
    }

    void stopSync() {
        running = false;
        if (syncThread && syncThread->joinable()) {
            syncThread->join();
            delete syncThread;
        }
    }

    void addSyncTask(const string& path, const string& action) {
        syncQueue.enqueue(new SyncTask(path, action));
    }

    void syncLoop() {
        while (running) {
            if (!syncQueue.isEmpty() && checkConnection()) {
                SyncTask* task = syncQueue.dequeue();
                processTask(task);
                delete task;
            }
            this_thread::sleep_for(chrono::seconds(5));
        }
    }

    bool checkConnection() {
        // Simulate connection with 75% success rate
        online = (rand() % 4) != 0;
        return online;
    }

    void processTask(SyncTask* task) {
        cout << "[Cloud Sync] Processing " << task->action
            << " for " << task->filePath << endl;
    }

    bool isOnline() const { return online; }
};

// User account information
class User {
public:
    string username;
    string password;
    string securityQuestion;
    string securityAnswer;
    time_t lastLogin;
    time_t lastLogout;
    bool isLoggedIn;
    LoggedInUserNode* loginNode;
    int permissions;

    User(string un, string pw, string q, string a) :
        username(un), password(pw), securityQuestion(q), securityAnswer(a),
        lastLogin(0), lastLogout(0), isLoggedIn(false), loginNode(NULL),
        permissions(PERM_READ) {
    }

    void setRole(const string& role) {
        permissions = 0;
        if (role == "admin") {
            permissions = PERM_READ | PERM_WRITE | PERM_EXECUTE | PERM_MODIFY_ACCESS;
        }
        else if (role == "editor") {
            permissions = PERM_READ | PERM_WRITE;
        }
        else { // viewer
            permissions = PERM_READ;
        }
    }

    bool hasPermission(Permission perm) const {
        return (permissions & perm) == perm;
    }
};

// User graph for connections and sharing
class UserGraph {
private:
    struct Connection {
        User* user;
        string filename;
        Connection* next;
        Connection(User* u, const string& f = "") : user(u), filename(f), next(NULL) {}
    };

    struct UserNode {
        User* user;
        Connection* connections;
        Connection* sharedFiles;

        UserNode(User* u) : user(u), connections(NULL), sharedFiles(NULL) {}

        ~UserNode() {
            Connection* conn = connections;
            while (conn) {
                Connection* temp = conn;
                conn = conn->next;
                delete temp;
            }
            conn = sharedFiles;
            while (conn) {
                Connection* temp = conn;
                conn = conn->next;
                delete temp;
            }
        }
    };

    HashTable<string, UserNode*> userMap;

    UserNode* getUserNode(const string& username) {
        UserNode* node;
        if (userMap.get(username, node)) {
            return node;
        }
        return NULL;
    }

public:
    ~UserGraph() {
        // HashTable will clean up UserNode pointers
    }

    void addUser(User* user) {
        UserNode* tmp;
        if (!userMap.get(user->username, tmp)) {
            userMap.insert(user->username, new UserNode(user));
        }
    }

    bool addConnection(const string& username1, const string& username2) {
        UserNode* user1 = getUserNode(username1);
        UserNode* user2 = getUserNode(username2);

        if (!user1 || !user2) {
            return false;
        }

        // Check if connection exists
        Connection* conn = user1->connections;
        while (conn) {
            if (conn->user->username == username2) {
                return true;
            }
            conn = conn->next;
        }

        // Add bidirectional connection
        Connection* newConn1 = new Connection(user2->user);
        newConn1->next = user1->connections;
        user1->connections = newConn1;

        Connection* newConn2 = new Connection(user1->user);
        newConn2->next = user2->connections;
        user2->connections = newConn2;

        return true;
    }

    bool shareFile(const string& sender, const string& receiver, const string& filename) {
        UserNode* senderNode = getUserNode(sender);
        UserNode* receiverNode = getUserNode(receiver);

        if (!senderNode || !receiverNode) {
            return false;
        }

        // Check connection exists
        bool connected = false;
        Connection* conn = senderNode->connections;
        while (conn) {
            if (conn->user->username == receiver) {
                connected = true;
                break;
            }
            conn = conn->next;
        }

        if (!connected) {
            return false;
        }

        // Check if file already shared
        Connection* shared = receiverNode->sharedFiles;
        while (shared) {
            if (shared->user->username == sender && shared->filename == filename) {
                return true;
            }
            shared = shared->next;
        }

        // Add to receiver's shared files
        Connection* newShare = new Connection(senderNode->user, filename);
        newShare->next = receiverNode->sharedFiles;
        receiverNode->sharedFiles = newShare;

        return true;
    }

    void getSharedFiles(const string& username, Queue<string>& result) {
        UserNode* user = getUserNode(username);
        if (!user) {
            return;
        }

        Connection* current = user->sharedFiles;
        while (current) {
            result.enqueue(current->user->username + " shared '" + current->filename + "' with you");
            current = current->next;
        }
    }

    void getConnections(const string& username, Queue<string>& result) {
        UserNode* user = getUserNode(username);
        if (!user) {
            return;
        }

        Connection* current = user->connections;
        while (current) {
            result.enqueue(current->user->username);
            current = current->next;
        }
    }

    bool isConnected(const string& user1, const string& user2) {
        UserNode* node1 = getUserNode(user1);
        if (!node1) {
            return false;
        }

        Connection* conn = node1->connections;
        while (conn) {
            if (conn->user->username == user2) {
                return true;
            }
            conn = conn->next;
        }
        return false;
    }
};

// Main File System Class
class FileSystem {
private:
    AVLTreeNode* root;
    AVLTreeNode* currentDir;
    User* currentUser;
    HashTable<string, User*> users;
    Stack<pair<FileMetadata*, string>> recycleBin;
    Queue<string> recentFiles;
    const int MAX_RECENT_FILES = 10;
    UserGraph userGraph;
    LoggedInUserNode* loggedInUsersHead;
    int loggedInUsersCount;
    CloudSync cloudSync;
    int adminCount; // To track admin count without lambda capture
    static FileSystem* instance; // Static instance for callback access

    AVLTreeNode* findNode(string path) {
        if (path == "/") {
            return root;
        }
        AVLTreeNode* temp = root;
        size_t start = 1, end;
        while ((end = path.find('/', start)) != string::npos) {
            string dirName = path.substr(start, end - start);
            temp = temp->find(dirName);
            if (!temp || !temp->isDirectory) {
                return NULL;
            }
            start = end + 1;
        }
        return temp->find(path.substr(start));
    }

    void clearLoggedInUsers() {
        LoggedInUserNode* current = loggedInUsersHead;
        while (current) {
            LoggedInUserNode* temp = current;
            current = current->next;
            delete temp;
        }
        loggedInUsersHead = NULL;
        loggedInUsersCount = 0;
    }

    void updateRecentFiles(const string& filename) {
        if (!currentUser) return;

        string filepath = getCurrentPath();
        if (filepath == "/") {
            filepath += filename;
        }
        else {
            filepath += "/" + filename;
        }

        // Check for duplicates
        Queue<string> temp;
        bool found = false;
        while (!recentFiles.isEmpty()) {
            string f = recentFiles.dequeue();
            if (f == filepath) {
                found = true;
            }
            else {
                temp.enqueue(f);
            }
        }

        // Restore non-duplicate entries
        while (!temp.isEmpty()) {
            recentFiles.enqueue(temp.dequeue());
        }

        // Add new file path if not found
        if (!found) {
            recentFiles.enqueue(filepath);
        }

        // Enforce size limit
        while (recentFiles.size() > MAX_RECENT_FILES) {
            recentFiles.dequeue();
        }
    }

    string getCurrentPath() {
        if (!currentDir) return "/";
        string path;
        AVLTreeNode* node = currentDir;
        while (node != NULL && node != root) {
            path = "/" + node->name + path;
            node = node->parent;
        }
        return path.empty() ? "/" : path;
    }

    bool isValidName(const string& name) {
        if (name.empty()) {
            return false;
        }
        for (size_t i = 0; i < name.length(); i++) {
            if (name[i] == '/') {
                return false;
            }
        }
        return true;
    }

    bool checkAccess(User* user, FileMetadata* file, Permission required) {
        if (file->owner == user->username) return true;
        if (!user->hasPermission(required)) return false;
        return true;
    }

    // Static callback for counting admins
    static void countAdminCallback(const string&, User* user) {
        if (user->hasPermission(PERM_MODIFY_ACCESS)) {
            instance->adminCount++;
        }
    }

    // Count admins
    int countAdmins() {
        adminCount = 0;
        users.iterate(countAdminCallback);
        return adminCount;
    }

public:
    FileSystem() : root(new AVLTreeNode("root", true)), currentDir(root),
        currentUser(NULL), loggedInUsersHead(NULL), loggedInUsersCount(0),
        adminCount(0) {
        instance = this;
        cloudSync.startSync();
    }

    ~FileSystem() {
        clearLoggedInUsers();
        delete root;
        cloudSync.stopSync();
    }

    void signup() {
        try {
            string un, pw, q, a, role;
            cout << "Username: ";
            // cin.ignore(numeric_limits<streamsize>::max(), '\n');
            getline(cin, un);
            if (cin.fail()) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                throw FileSystemException("Invalid username input");
            }
            if (un.empty()) {
                throw FileSystemException("Username cannot be empty");
            }

            cout << "Password: ";
            getline(cin, pw);
            if (cin.fail()) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                throw FileSystemException("Invalid password input");
            }
            if (pw.empty()) {
                throw FileSystemException("Password cannot be empty");
            }

            cout << "Security Question: ";
            getline(cin, q);
            if (q.empty()) {
                throw FileSystemException("Security question cannot be empty");
            }

            cout << "Answer: ";
            getline(cin, a);
            if (a.empty()) {
                throw FileSystemException("Security answer cannot be empty");
            }

            cout << "Role (admin/editor/viewer): ";
            getline(cin, role);
            if (role.empty()) {
                throw FileSystemException("Role cannot be empty");
            }

            if (!isValidName(un)) {
                throw FileSystemException("Invalid username (contains '/' or is empty)");
            }

            User* tmp;
            if (users.get(un, tmp)) {
                throw FileSystemException("User already exists");
            }

            if (pw.length() < 6) {
                throw FileSystemException("Password must be at least 6 characters");
            }

            User* newUser = new User(un, pw, q, a);
            users.insert(un, newUser);
            userGraph.addUser(newUser);

            // Default first user to admin if no users exist
            if (users.get(un, tmp) && countAdmins() == 0) {
                setUserRole(un, "admin");
            }
            else {
                setUserRole(un, role);
            }

            cout << "Signup successful!\n";
        }
        catch (const FileSystemException& e) {
            cerr << "Error: " << e.what() << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }

    bool login(string un, string pw) {
        try {
            if (un.empty()) {
                throw FileSystemException("Username cannot be empty");
            }
            if (pw.empty()) {
                throw FileSystemException("Password cannot be empty");
            }

            User* user;
            if (!users.get(un, user)) {
                throw FileSystemException("User not found");
            }

            if (user->password != pw) {
                throw FileSystemException("Invalid password");
            }

            if (user->isLoggedIn) {
                throw FileSystemException("User already logged in");
            }

            LoggedInUserNode* newNode = new LoggedInUserNode(user);
            newNode->next = loggedInUsersHead;
            loggedInUsersHead = newNode;
            user->loginNode = newNode;

            currentUser = user;
            user->lastLogin = time(NULL);
            user->isLoggedIn = true;
            loggedInUsersCount++;

            cout << "Login successful! Welcome " << un << ".\n";
            return true;
        }
        catch (const FileSystemException& e) {
            cerr << "Error: " << e.what() << endl;
            return false;
        }
    }

    void logout() {
        if (loggedInUsersCount == 0) {
            cout << "No users are currently logged in.\n";
            return;
        }

        if (loggedInUsersCount == 1) {
            User* user = loggedInUsersHead->user;
            user->lastLogout = time(NULL);
            user->isLoggedIn = false;

            delete loggedInUsersHead;
            loggedInUsersHead = NULL;
            loggedInUsersCount = 0;

            if (currentUser == user) {
                currentUser = NULL;
            }

            cout << "User " << user->username << " logged out successfully.\n";
            return;
        }

        cout << "\nMultiple users are logged in. Select which user to logout:\n";
        LoggedInUserNode* current = loggedInUsersHead;
        int index = 1;
        while (current) {
            cout << index++ << ". " << current->user->username << "\n";
            current = current->next;
        }

        int choice;
        cout << "Enter your choice (1-" << loggedInUsersCount << "): ";
        cin >> choice;

        while (cin.fail() || choice < 1 || choice > loggedInUsersCount) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. Please enter a number between 1 and "
                << loggedInUsersCount << ": ";
            cin >> choice;
        }

        LoggedInUserNode* prev = NULL;
        current = loggedInUsersHead;
        for (int i = 1; i < choice; i++) {
            prev = current;
            current = current->next;
        }

        User* userToLogout = current->user;
        userToLogout->lastLogout = time(NULL);
        userToLogout->isLoggedIn = false;
        loggedInUsersCount--;

        if (prev) {
            prev->next = current->next;
        }
        else {
            loggedInUsersHead = current->next;
        }

        if (currentUser == userToLogout) {
            currentUser = loggedInUsersHead ? loggedInUsersHead->user : NULL;
            if (currentUser) {
                cout << "Current user switched to " << currentUser->username << "\n";
            }
        }

        delete current;
        cout << "User " << userToLogout->username << " logged out successfully.\n";
    }

    void setUserRole(const string& username, const string& role) {
        try {
            if (!currentUser) {
                throw FileSystemException("Login first");
            }

            // Manual lowercase conversion
            string roleLower = role;
            for (char& c : roleLower) {
                if (c >= 'A' && c <= 'Z') {
                    c = c + ('a' - 'A');
                }
            }

            if (roleLower != "admin" && roleLower != "editor" && roleLower != "viewer") {
                throw FileSystemException("Invalid role. Must be admin, editor, or viewer");
            }

            User* user;
            if (!users.get(username, user)) {
                throw FileSystemException("User not found");
            }

            // Allow first admin or users with PERM_MODIFY_ACCESS
            if (countAdmins() == 0 || (currentUser->hasPermission(PERM_MODIFY_ACCESS) && currentUser->username != username)) {
                // Prevent self-demotion if only admin
                if (currentUser->username == username && roleLower != "admin" && countAdmins() == 1) {
                    throw FileSystemException("Cannot demote the only admin");
                }

                user->setRole(roleLower);
                cout << "DEBUG: Role set for " << username << " to " << roleLower << ", permissions: 0x" << hex << user->permissions << dec << endl;
                cout << "Role for " << username << " set to " << roleLower << ".\n";
                cout << "New permissions: ";
                bool hasPerm = false;
                if (user->hasPermission(PERM_READ)) { cout << "READ "; hasPerm = true; }
                if (user->hasPermission(PERM_WRITE)) { cout << "WRITE "; hasPerm = true; }
                if (user->hasPermission(PERM_EXECUTE)) { cout << "EXECUTE "; hasPerm = true; }
                if (user->hasPermission(PERM_MODIFY_ACCESS)) { cout << "MODIFY_ACCESS "; hasPerm = true; }
                if (!hasPerm) cout << "NONE";
                cout << endl;
            }
            else {
                throw FileSystemException("You don't have permission to modify user roles");
            }
        }
        catch (const FileSystemException& e) {
            cerr << "Error: " << e.what() << endl;
        }
    }

    void resetPassword() {
        try {
            string username, answer, newPassword;
            cout << "Enter username: ";
            getline(cin, username);
            if (username.empty()) {
                throw FileSystemException("Username cannot be empty");
            }

            User* user;
            if (!users.get(username, user)) {
                throw FileSystemException("User not found");
            }

            cout << "Security Question: " << user->securityQuestion << endl;
            cout << "Answer: ";
            getline(cin, answer);
            if (answer.empty()) {
                throw FileSystemException("Answer cannot be empty");
            }

            if (answer != user->securityAnswer) {
                throw FileSystemException("Incorrect security answer");
            }

            cout << "Enter new password (minimum 6 characters): ";
            getline(cin, newPassword);
            if (newPassword.length() < 6) {
                throw FileSystemException("Password must be at least 6 characters");
            }

            user->password = newPassword;
            cout << "Password reset successfully for " << username << ".\n";
        }
        catch (const FileSystemException& e) {
            cerr << "Error: " << e.what() << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    }

    void createFile(string name, string type) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }
        if (!isValidName(name)) {
            cout << "Invalid file name.\n";
            return;
        }
        FileMetadata* existingFile;
        if (currentDir->files.get(name, existingFile)) {
            cout << "File already exists.\n";
            return;
        }
        if (currentDir->find(name)) {
            cout << "A directory with this name already exists.\n";
            return;
        }
        FileMetadata* file = new FileMetadata(name, type, currentUser->username);
        currentDir->files.insert(name, file);
        updateRecentFiles(name);
        cloudSync.addSyncTask(getCurrentPath() + "/" + name, "upload");
        cout << "File created: " << name << endl;
    }

    void deleteFile(string name) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }
        FileMetadata* file;
        if (currentDir->files.get(name, file)) {
            if (!checkAccess(currentUser, file, PERM_WRITE)) {
                cout << "You don't have permission to delete this file.\n";
                return;
            }
            recycleBin.push(make_pair(file, getCurrentPath()));
            currentDir->files.remove(name);
            cloudSync.addSyncTask(getCurrentPath() + "/" + name, "delete");
            cout << "File moved to recycle bin: " << name << endl;
        }
        else {
            cout << "File not found.\n";
        }
    }

    void restoreFile() {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }
        if (!recycleBin.isEmpty()) {
            auto entry = recycleBin.pop();
            string originalPath = entry.second;
            FileMetadata* file = entry.first;

            AVLTreeNode* dir = findNode(originalPath);
            if (!dir) {
                cout << "Original directory no longer exists. Restoring to current directory.\n";
                dir = currentDir;
            }

            FileMetadata* existingFile;
            if (dir->files.get(file->name, existingFile)) {
                cout << "A file with this name already exists in the target directory.\n";
                cout << "Please rename the file before restoring.\n";
                recycleBin.push(entry);
                return;
            }

            dir->files.insert(file->name, file);
            updateRecentFiles(file->name);
            cloudSync.addSyncTask(getCurrentPath() + "/" + file->name, "upload");
            cout << "File restored: " << file->name << " to "
                << (dir == root ? "/" : dir->name) << endl;
        }
        else {
            cout << "Recycle bin is empty.\n";
        }
    }

    void listDirectory() {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }
        if (!currentDir) {
            cout << "Error: No current directory set!\n";
            return;
        }

        cout << "\nContents of " << getCurrentPath() << ":\n";

        // In-order traversal of AVL tree for directories
        Stack<AVLTreeNode*> stack;
        AVLTreeNode* current = currentDir;
        bool hasContents = false;

        while (current || !stack.isEmpty()) {
            while (current) {
                stack.push(current);
                current = current->left;
            }

            current = stack.pop();
            if (current->isDirectory && current != currentDir) {
                cout << "[DIR]  " << current->name << "\n";
                hasContents = true;
            }
            current = current->right;
        }

        // List files from HashTable
        currentDir->files.iterate([](const string& name, FileMetadata* file) {
            cout << "[FILE] " << name << " (Type: " << file->type << ", Owner: " << file->owner << ")\n";
            });
        hasContents = true; // Assume files exist if iterate was called

        if (!hasContents) {
            cout << "Directory is empty.\n";
        }
        else {
            cout << "End of directory listing.\n";
        }
    }

    void changeDirectory(const string& path) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        if (path.empty()) {
            cout << "Path cannot be empty.\n";
            return;
        }

        if (path == "/") {
            currentDir = root;
            cout << "Current directory: /\n";
            return;
        }

        if (path == "..") {
            if (currentDir != root) {
                currentDir = currentDir->parent;
            }
            cout << "Current directory: " << getCurrentPath() << "\n";
            return;
        }

        AVLTreeNode* target = NULL;
        if (path[0] == '/') {
            target = findNode(path);
        }
        else {
            target = currentDir->find(path);
        }

        if (target && target->isDirectory) {
            currentDir = target;
            cout << "Current directory: " << getCurrentPath() << endl;
        }
        else {
            cout << "Directory not found: " << path << endl;
        }
    }

    void makeDirectory(const string& dirName) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        if (!isValidName(dirName)) {
            cout << "Invalid directory name.\n";
            return;
        }

        if (currentDir->find(dirName)) {
            cout << "Directory already exists.\n";
            return;
        }

        FileMetadata* existingFile;
        if (currentDir->files.get(dirName, existingFile)) {
            cout << "A file with this name already exists.\n";
            return;
        }

        AVLTreeNode* newNode = new AVLTreeNode(dirName, true, currentDir);
        currentDir = currentDir->insert(newNode)->balance();
        cout << "Directory created: " << dirName << endl;
    }

    void moveFile(const string& source, const string& destPath) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        FileMetadata* file;
        if (!currentDir->files.get(source, file)) {
            cout << "Source file not found.\n";
            return;
        }

        if (!checkAccess(currentUser, file, PERM_WRITE)) {
            cout << "You don't have permission to move this file.\n";
            return;
        }

        AVLTreeNode* destDir = findNode(destPath);
        if (!destDir || !destDir->isDirectory) {
            cout << "Destination directory not found.\n";
            return;
        }

        FileMetadata* existingFile;
        if (destDir->files.get(source, existingFile)) {
            cout << "File already exists in destination directory.\n";
            return;
        }

        currentDir->files.remove(source);
        destDir->files.insert(source, file);
        cloudSync.addSyncTask(getCurrentPath() + "/" + source, "delete");
        cloudSync.addSyncTask(destPath + "/" + source, "upload");
        cout << "File moved successfully to " << destPath << endl;
    }

    void compressFile(const string& name, const string& method = "RLE") {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        FileMetadata* file;
        if (currentDir->files.get(name, file)) {
            if (!checkAccess(currentUser, file, PERM_WRITE)) {
                cout << "You don't have permission to modify this file.\n";
                return;
            }

            if (method != "RLE" && method != "DICT") {
                cout << "Invalid compression method. Use RLE or DICT.\n";
                return;
            }

            file->compress(method);
            cloudSync.addSyncTask(getCurrentPath() + "/" + name, "upload");
            cout << "File compressed using " << method << " method.\n";
        }
        else {
            cout << "File not found.\n";
        }
    }

    void decompressFile(const string& name) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        FileMetadata* file;
        if (currentDir->files.get(name, file)) {
            if (!checkAccess(currentUser, file, PERM_WRITE)) {
                cout << "You don't have permission to modify this file.\n";
                return;
            }

            file->decompress();
            cloudSync.addSyncTask(getCurrentPath() + "/" + name, "upload");
            cout << "File decompressed.\n";
        }
        else {
            cout << "File not found.\n";
        }
    }

    void addConnection(string otherUser) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        if (currentUser->username == otherUser) {
            cout << "Cannot connect to yourself.\n";
            return;
        }

        User* user;
        if (!users.get(otherUser, user)) {
            cout << "User " << otherUser << " does not exist.\n";
            return;
        }

        if (userGraph.addConnection(currentUser->username, otherUser)) {
            cout << "Connection added with " << otherUser << endl;
        }
        else {
            cout << "You are already connected with " << otherUser << endl;
        }
    }

    void shareFile(string filename, string receiver) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        if (currentUser->username == receiver) {
            cout << "Cannot share file with yourself.\n";
            return;
        }

        FileMetadata* file;
        if (!currentDir->files.get(filename, file)) {
            cout << "File not found.\n";
            return;
        }

        User* user;
        if (!users.get(receiver, user)) {
            cout << "User " << receiver << " does not exist.\n";
            return;
        }

        if (!userGraph.isConnected(currentUser->username, receiver)) {
            cout << "You must first connect with " << receiver << " before sharing files.\n";
            return;
        }

        if (userGraph.shareFile(currentUser->username, receiver, filename)) {
            cout << "File '" << filename << "' shared with " << receiver << endl;
        }
        else {
            cout << "Failed to share file with " << receiver << endl;
        }
    }

    void viewSharedFiles() {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        Queue<string> sharedFiles;
        userGraph.getSharedFiles(currentUser->username, sharedFiles);

        if (sharedFiles.isEmpty()) {
            cout << "No files have been shared with you.\n";
            return;
        }

        cout << "Files shared with you:\n";
        while (!sharedFiles.isEmpty()) {
            cout << "- " << sharedFiles.dequeue() << endl;
        }
    }

    void viewConnections() {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        Queue<string> connections;
        userGraph.getConnections(currentUser->username, connections);

        if (connections.isEmpty()) {
            cout << "You have no connections yet.\n";
            return;
        }

        cout << "Your connections:\n";
        while (!connections.isEmpty()) {
            cout << "- " << connections.dequeue() << endl;
        }
    }

    void displayFile(string name) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        FileMetadata* file;
        if (currentDir->files.get(name, file)) {
            if (!checkAccess(currentUser, file, PERM_READ)) {
                cout << "You don't have permission to view this file.\n";
                return;
            }

            file->lastAccessed = time(NULL);
            file->accessCount++;
            updateRecentFiles(name);

            cout << "\n--- File Details ---\n";
            cout << "Name: " << file->name << endl;
            cout << "Type: " << file->type << endl;
            cout << "Owner: " << file->owner << endl;
            cout << "Size: " << file->size << " bytes" << endl;
            cout << "Access count: " << file->accessCount << endl;

            if (file->versions) {
                if (file->versions->compressed) {
                    cout << "Status: Compressed (" << file->versions->compressionType << ")\n";
                }
                cout << "\nCurrent Version Content:\n";
                cout << file->versions->content << endl;

                cout << "\nVersion History:\n";
                FileVersion* version = file->versions;
                while (version) {
                    time_t t = version->timestamp;
                    time_t days = t / 86400;
                    time_t hours = (t % 86400) / 3600;
                    cout << "- " << days << " days, " << hours << " hours old ("
                        << version->content.length() << " chars)";
                    if (version->compressed) {
                        cout << " [Compressed: " << version->compressionType << "]";
                    }
                    cout << "\n";
                    version = version->prev;
                }
            }
            else {
                cout << "\nNo content available.\n";
            }
        }
        else {
            cout << "File not found in current directory.\n";
        }
    }

    bool searchFile(string name) {
        if (!currentUser) {
            cout << "Login first.\n";
            return false;
        }

        FileMetadata* file;
        bool found = currentDir->files.get(name, file);
        if (found) {
            if (!checkAccess(currentUser, file, PERM_READ)) {
                cout << "File found but you don't have permission to view it.\n";
                return false;
            }
            cout << "File found: " << name << " (Type: " << file->type
                << ", Owner: " << file->owner << ")\n";
        }
        else {
            cout << "File not found in current directory.\n";
        }
        return found;
    }

    void readFile(string name) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        FileMetadata* file;
        if (currentDir->files.get(name, file)) {
            if (!checkAccess(currentUser, file, PERM_READ)) {
                cout << "You don't have permission to read this file.\n";
                return;
            }

            file->lastAccessed = time(NULL);
            file->accessCount++;
            updateRecentFiles(name);

            if (file->versions) {
                cout << "\n--- File Content ---\n";
                cout << file->versions->content << endl;
                cout << "-------------------\n";
            }
            else {
                cout << "File is empty.\n";
            }
        }
        else {
            cout << "File not found.\n";
        }
    }

    void updateFile(const string& name, const string& newContent) {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        FileMetadata* file;
        if (currentDir->files.get(name, file)) {
            if (!checkAccess(currentUser, file, PERM_WRITE)) {
                cout << "You don't have permission to modify this file.\n";
                return;
            }
            file->addVersion(newContent);
            updateRecentFiles(name);
            cloudSync.addSyncTask(getCurrentPath() + "/" + name, "upload");
            cout << "File '" << name << "' updated successfully.\n";
        }
        else {
            cout << "File not found.\n";
        }
    }

    void viewRecentFiles() {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }

        if (recentFiles.isEmpty()) {
            cout << "No recent files.\n";
            return;
        }

        cout << "Recently accessed files (newest first) [Queue size: " << recentFiles.size() << "]:\n";

        Queue<string> temp = recentFiles;
        Stack<string> reverseStack;

        while (!temp.isEmpty()) {
            reverseStack.push(temp.dequeue());
        }

        while (!reverseStack.isEmpty()) {
            cout << "- " << reverseStack.pop() << endl;
        }
    }

    void checkSyncStatus() {
        cout << "Cloud Sync Status: " << (cloudSync.isOnline() ? "Online" : "Offline") << endl;
    }

    void debugPrintStructure() {
        if (!currentUser) {
            cout << "Login first.\n";
            return;
        }
        cout << "\n=== File System Structure ===\n";
        debugPrintTree(root);
        cout << "============================\n";
    }

private:
    void debugPrintTree(AVLTreeNode* node, int depth = 0) {
        if (!node) return;
        debugPrintTree(node->left, depth + 1);
        cout << string(depth * 2, ' ') << "- " << node->name
            << (node->isDirectory ? "/" : "") << endl;
        debugPrintTree(node->right, depth + 1);
    }
};

// Static instance definition
FileSystem* FileSystem::instance = NULL;

void printdrivesystem()
{

    cout << "                                     ____________   \n";
    cout << "                                    /\\\033[42m          \033[0m/\\   \n";
    cout << "                                   /\033[102m  \033[0m\\\033[42m        \033[0m/\033[43m  \033[0m\\   \n";
    cout << "                                  /\033[102m    \033[0m\\\033[42m      \033[0m/\033[43m    \033[0m\\   \n";
    cout << "                                 /\033[102m      \033[0m\\\033[42m    \033[0m/\033[43m      \033[0m\\   \n";
    cout << "                                /\033[102m        \033[0m\\\033[42m  \033[0m/\033[43m        \033[0m\\   \n";
    cout << "                               /\033[102m          \033[0m\\\033[42m\033[0m/\033[43m          \033[0m\\   \n";
    cout << "                              /\033[102m           \033[0m/\\\033[43m           \033[0m\\   \n";
    cout << "                             /\033[102m           \033[0m/  \\\033[43m           \033[0m\\   \n";
    cout << "                            /\033[102m           \033[0m/    \\\033[43m           \033[0m\\   \n";
    cout << "                           /\033[102m           \033[0m/      \\\033[43m           \033[0m\\   \n";
    cout << "                          /\033[102m           \033[0m/        \\\033[43m           \033[0m\\   \n";
    cout << "                         /\033[102m           \033[0m/          \\\033[43m           \033[0m\\   \n";
    cout << "                        /\033[102m           \033[0m/            \\\033[43m           \033[0m\\   \n";
    cout << "                       /\033[102m           \033[0m/              \\\033[43m           \033[0m\\   \n";
    cout << "                      /\033[102m           \033[0m/                \\\033[43m           \033[0m\\   \n";
    cout << "                     /\033[102m           \033[0m/                  \\\033[43m           \033[0m\\   \n";
    cout << "                    /\033[102m___________\033[0m/____________________\\\033[43m___________\033[0m\\   \n";
    cout << "                    \\\033[44m          \033[0m/\033[104m                      \033[0m\\\033[41m          \033[0m/    \n";
    cout << "                     \\\033[44m        \033[0m/\033[104m                        \033[0m\\\033[41m        \033[0m/    \n";
    cout << "                      \\\033[44m      \033[0m/\033[104m                          \033[0m\\\033[41m      \033[0m/    \n";
    cout << "                       \\\033[44m    \033[0m/\033[104m                            \033[0m\\\033[41m    \033[0m/    \n";
    cout << "                        \\\033[44m  \033[0m/\033[104m                              \033[0m\\\033[41m  \033[0m/    \n";
    cout << "                         \\\033[44m\033[0m/\033[104m________________________________\033[0m\\\033[41m\033[0m/    \n";


}
// Main program
int main() {
    FileSystem fs;
    string username, password, fileName, fileType, targetUser, newContent, path, role, method;
    printdrivesystem();
    while (true) {
        try {
            int choice;
            cout << "\n\t\t\t     \033[36m=== GOOGLE DRIVE SYSTEM ===\n";
            cout << "1.  Sign Up\n";
            cout << "2.  Login\n";
            cout << "3.  Logout\n";
            cout << "4.  Create File\n";
            cout << "5.  Delete File\n";
            cout << "6.  Restore File\n";
            cout << "7.  List Directory\n";
            cout << "8.  Change Directory\n";
            cout << "9.  Make Directory\n";
            cout << "10. Move File\n";
            cout << "11. Add Connection\n";
            cout << "12. Share File\n";
            cout << "13. View Shared Files\n";
            cout << "14. View Connections\n";
            cout << "15. Display File\n";
            cout << "16. Search File\n";
            cout << "17. Read File\n";
            cout << "18. Update File\n";
            cout << "19. View Recent Files\n";
            cout << "20. Set User Role\n";
            cout << "21. Compress File\n";
            cout << "22. Decompress File\n";
            cout << "23. Check Sync Status\n";
            cout << "24. Reset Password\n";
            cout << "25. Exit\033[0m\n";
            cout << "\033[35mEnter your choice: ";

            cin >> choice;
            if (cin.fail()) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                throw FileSystemException("Invalid input. Please enter a number");
            }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            if (choice < 1 || choice > 26) {
                throw FileSystemException("Invalid choice. Please enter a number between 1 and 26");
            }
            cout << "\033[0m";
            switch (choice) {
            case 1:
                cout << "\033[31m";
                fs.signup();
                cout << "\033[0m";
                break;
            case 2:
                cout << "\033[31mUsername: ";
                getline(cin, username);
                cout << "Password: ";
                getline(cin, password);
                fs.login(username, password);
                cout << "\033[0m";
                break;
            case 3:
                cout << "\033[33m";
                fs.logout();
                cout << "\033[0m";
                break;
            case 4:
                cout << "\033[31mEnter file name: ";
                getline(cin, fileName);
                cout << "Enter file type: ";
                getline(cin, fileType);
                fs.createFile(fileName, fileType);
                cout << "\033[0m";
                break;
            case 5:
                cout << "\033[31mEnter file name to delete: ";
                getline(cin, fileName);
                cout << "\033[0m";
                cout << "\033[33m";
                fs.deleteFile(fileName);
                cout << "\033[0m";
                break;
            case 6:
                cout << "\033[32m";
                fs.restoreFile();
                cout << "\033[0m";
                break;
            case 7:
                cout << "\033[34m";
                fs.listDirectory();
                cout << "\033[0m";
                break;
            case 8:
                cout << "\033[31mEnter path: ";
                getline(cin, path);
                fs.changeDirectory(path);
                cout << "\033[0m";
                break;
            case 9:
                cout << "\033[31mEnter directory name: ";
                getline(cin, path);
                fs.makeDirectory(path);
                cout << "\033[0m";
                break;
            case 10:
                cout << "\033[31mEnter file name to move: ";
                getline(cin, fileName);
                cout << "Enter destination path: ";
                getline(cin, path);
                fs.moveFile(fileName, path);
                cout << "\033[0m";
                break;
            case 11:
                cout << "\033[31mEnter username to connect with: ";
                getline(cin, targetUser);
                fs.addConnection(targetUser);
                cout << "\033[0m";
                break;
            case 12:
                cout << "\033[31mEnter file name to share: ";
                getline(cin, fileName);
                cout << "Enter username to share with: ";
                getline(cin, targetUser);
                fs.shareFile(fileName, targetUser);
                cout << "\033[0m";
                break;
            case 13:
                cout << "\033[32m";
                fs.viewSharedFiles();
                cout << "\033[0m";
                break;
            case 14:
                cout << "\033[32m";
                fs.viewConnections();
                cout << "\033[0m";
                break;
            case 15:
                cout << "\033[31mEnter file name to display:\033[0m";
                getline(cin, fileName);
                cout << "\033[34m";
                fs.displayFile(fileName);
                cout << "\033[0m";
                break;
            case 16:
                cout << "\033[31mEnter file name to search: ";
                getline(cin, fileName);
                cout << "\033[0m";
                cout << "\033[34m";
                fs.searchFile(fileName);
                cout << "\033[0m";
                break;
            case 17:
                cout << "\033[31mEnter file name to read: ";
                getline(cin, fileName);
                fs.readFile(fileName);
                cout << "\033[0m";
                break;
            case 18:
                cout << "\033[31mEnter file name to update: ";
                getline(cin, fileName);
                cout << "Enter new content: ";
                getline(cin, newContent);
                fs.updateFile(fileName, newContent);
                cout << "\033[0m";
                break;
            case 19:
                cout << "\033[32m";
                fs.viewRecentFiles();
                cout << "\033[0m";
                break;
            case 20:
                cout << "\033[31mEnter username: ";
                getline(cin, username);
                cout << "Enter role (admin/editor/viewer): ";
                getline(cin, role);
                fs.setUserRole(username, role);
                cout << "\033[0m";
                break;
            case 21:
                cout << "\033[31mEnter file name: ";
                getline(cin, fileName);
                cout << "Enter method (RLE/DICT): ";
                getline(cin, method);
                fs.compressFile(fileName, method);
                cout << "\033[0m";
                break;
            case 22:
                cout << "\033[31mEnter file name: ";
                getline(cin, fileName);
                fs.decompressFile(fileName);
                cout << "\033[0m";
                break;
            case 23:
                cout << "\033[32m";
                fs.checkSyncStatus();
                cout << "\033[0m";
                break;
            case 24:
                cout << "\033[31m";
                fs.resetPassword();
                cout << "\033[0m";
                break;
            case 25:
                cout << "\033[32m";
                cout << "Exiting program.\n";
                cout << "\033[0m";
                return 0;
            }
        }
        catch (const FileSystemException& e) {
            cerr << "Error: " << e.what() << endl;
        }
        catch (const std::exception& e) {
            cerr << "System error: " << e.what() << endl;
        }
        catch (...) {
            cerr << "Unknown error occurred" << endl;
        }
    }
    return 0;
}

