# 编译器
CXX = g++
# 编译选项
CXXFLAGS = -std=c++17
# 输出可执行文件的名称
TARGET = agent
# 源文件
SRCS = main.cpp caes.cpp info.cpp Log.cpp socket_manager.cpp socket_send.cpp task.cpp tools.cpp
# 目标文件
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

# 生成目标文件
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

# g++ -std=c++17 -o agent main.cpp caes.cpp info.cpp Log.cpp socket_manager.cpp socket_send.cpp task.cpp tools.cpp