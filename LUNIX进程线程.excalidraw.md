---

excalidraw-plugin: parsed
tags: [excalidraw]

---
==⚠  Switch to EXCALIDRAW VIEW in the MORE OPTIONS menu of this document. ⚠== You can decompress Drawing data with the command palette: 'Decompress current Excalidraw file'. For more info check in plugin settings under 'Saving'


# Excalidraw Data

## Text Elements
1.进程描述符
    pid
2.进程的创建
    fork()
3.进程的结束与回收
    wait()
    waitpid()
4.exec函数族 ^D3HiHmcG

进程状态

R 运行/就绪  子进程正常运行，无需处理
S 阻塞态 子进程等待资源，未退出
Z 僵尸态  子进程已退出，父进程未回收，占用PID资源
T 暂停    子进程被信号暂停 ^TlQqVvSt

僵尸进程的危害
    ·占用系统pid资源，若大量堆积无法创建新进程
    ·只有父进程回收（wait/waitpid）
    或父进程退出（由系统接管）,僵尸进程才会消失 ^SxiSqGGb

wstatus 的核心宏
WIFEXITED(status)   //判断子进程是否正常退出（如exit()）

WEXITSTATUS(status) //若正常退出，获取退出码（exit(n)中的n）

WIFSIGNALED(status) //判断子进程是否被信号终止(如kill -9)

WTERMSIG(status) //若被信号终止，获取终止信号的编号 ^G3by3Th8

wait的四个核心问题

问题1：wait是阻塞调用
    原因：wait没有非阻塞选项，只要没有子进程退出，
父进程会一直卡在wait运行，无法执行后续逻辑。
    临时方案：后续用waitpid的WNOHANG参数实现非阻塞

问题2：wait只能等待“任意一个”子进程
    原因：1次wait只能回收一次子进程，剩余子进程退出后
变成僵尸
    临时方案：循环调用wait,直到所有子进程被回收

问题3：无子女进程时调用wait会报错
    原因：wait的核心逻辑是等待子进程，无子女进程时调用
会触发ECHILD错误
    解决方案：调用wait前可先判断是否有子进程（或捕获ECHILD错误）
问题4：无法直接通过status判断退出状态
    原因：status是一个整数，低8位存储”信号终止信息“，次低8位存储
”正常退出码“，直接打印无意义，必须用宏解析
    解决方案：宏解析
 ^D2GRJuE4

掌握wait函数目标
1.理解wait函数的作用(阻塞等待+回收僵尸+获取退出状态)
2.会wait函数回收子进程，清除僵尸
3.会解析子进程的退出状态（正常退出/信号终止） ^kvJRlSk0

pid_t waitpid(pid_t pid,int *status, int options); ^2SgixEIe

wait(int *wstatus); ^M2dKBq6V

pid_t waitpid(pid_t pid,int *wstatus, int options); ^WpYOL7VN

核心：指定要等待的子进程
-pid > 0:等待PID等于pid的子进程
-pid=-1:等待任意子进程（等价于wait）
-pid=0:等待同组的所有子进程 ^XS5dgQJI

控制等待模式
-WNOHANG:非阻塞模式（无子进程退出则返回0）
-0：阻塞模式（等价于wait） ^M6PO0IYP

waitpid(pid,NULL,0) //阻塞等待指定子进程
waitpid(-1,NULL,0)//阻塞等待任意子进程
waitpid(-1,NULL,WNOHANG) //非阻塞等待任意子进程 ^j81kZYjb

waitpid”如何指定子进程等待“
1.阻塞等待指定子进程
2.非阻塞等待指定子进程
3.通过循环解决多子进程僵尸 ^HuSYzbP4

system函数原型

#include <stdio.h>
int system(const char *command) ^Qqg2AyUq

system()的执行流程
1.fork()创建子进程
2.子进程中调用execve("/bin/sh",["sh","-c","command",NULL],环境变量)，
通过shell解析并执行命令
3.父进程调用waitpid()等待子进程退出，返回子进程的退出状态 ^Udx1BNcK

深入exec函数族
·理解exec函数族的核心作用（替换进程映像）
·掌握6个exec函数的区别与用法
·解决exec调用的常见问题 ^0TiDeaS4

#include <unistd.h>
int execl(const char *path, const char *arg, ...)
int execp
int execvp
 ^HDM5QT2p

exec常见问题与避坑
问题1：忘记在fork子进程中调用exec
问题2：参数列表/数组未以NULL结尾
问题3：exec不支持shell特性（管道/重定向）
问题4：忽略exec的错误处理 ^dV5qqYOA



僵尸进程：子进程结束但父进程没有回收
孤儿进程：
    父进程先于子进程退出，子进程被init进程
（PID=1）接管
    特征：子进程的PPID变为1
    与僵尸的区别：孤儿 ”活着的进程“状态S/R
                     僵尸 ”已退出未收回的进程“ 状态Z
    作用：守护进程第一步就是孤儿进程，避免父进程与
    终端关联

 ^x73LHGW8

守护进程特征

1.后台运行- 无终端交互，用ps -ef可查，jobs不可查
2.脱离终端-不受终端信号（ctrl+c）影响，终端关闭
不影响运行
3.独立会话（session）-不属于任何终端的会话组，避
免终端退出时被回收
4.工作目录稳定-通常切换到/或/var/run,避免终端退出
时被回收
5.权限可控-重置umask,避免继承父进程的权限掩码导致
文件创建权限异常
6.关闭无关文件描述符-关闭stdin/stdout/stderr,脱离
终端的io关联 ^iUMXe95q

实现六步
步骤1：fork创建子进程，父进程退出（生成孤儿进程）
·作用：
    子进程继承父进程的进程组，但脱离父进程
的终端关联；
    父进程退出后，子进程变成孤儿进程（PPID=1）
步骤2：setsid创建新会话（脱离终端）
·作用：
    创建新会话（session），子进程成为会话首进程、
进程组首进程，彻底脱离原终端。
    只有非进程组首进程才能调用setsid(步骤1的fork
保证了这一点)
步骤3：再次fork（可选，增强稳定性）
步骤4：chdir切换工作目录
·作用：避免父进程的工作目录是挂载点，卸载后导致
进程异常；通常切换到/或/var/run
步骤5：umask重置权限掩码
·作用：父进程的umask会影响子进程创建文件的权限，
重置为0可自定义权限
步骤6：关闭所有无关文件描述符
作用：关闭继承自父进程的文件描述符，尤其是stdin/
stdout/stderr,脱离io关联
核心：先获取系统最大文件描述符，循环关闭；或直接关闭
0、1、2（标准io）
 ^IBcc6Mrb

setsid()
 ^jL4b80zC

开始 ^11rwR3Mv

fork()
exit() ^dtvKdKtm

setsid() ^RWvDspA7

chdir("/") ^48SBpAzM

umask(0) ^YUutFg6I

close() ^xXvV4Kya

结束 ^1ra9J8fu

信号
信号是linux内核向进程发送的异步通知，用于告知进程发生了个某个事件
（如用户按ctrl+c、进程访问非法内存、其他进程发送指令）
-特征：异步性 
-本质：整数标识（每个信号对应一个唯一整数，如SIGTERM=15）
-核心行为：进程收到信号后，默认有3种处理方式：
·执行默认动作（如SIGINT默认终止进程、SIGCHLD默认忽略）
·忽略信号（进程无任何反应）
·自定义处理（执行用户编写的信号处理函数） ^o92GYbHn

信号集与信号掩码
信号集（sigset_t）:linux内核定义的数据结构，用于存储多个信号
作用：批量管理信号
核心操作函数：

sigemptyset(&set)    清空信号集（所有位设为0）

sigfillset(&set)      填满信号集（所有位设为1）

sigaddset(&set, sig) 向信号集添加信号sig(对应位设为1)

sigdelset(&set, sig)  向信号集删除信号sig(对应位设为0)

sigismember(&set, sig) 判断信号sig是否在集合中（返回 1 = 是，0 = 否） ^R3j5q4O1

信号掩码（进程的信号屏蔽字）
信号掩码是进程的一个属性，本质是信号集，用于指定“哪些信号会被进程暂时阻塞”
·核心规则：
1.被阻塞的信号不会立即被进程处理，会被内核暂存，直到掩码解除
2.SIGKILL和SIGSTOP无法被阻塞
3.修改信号掩码的函数：sigpromask()核心、pthread_sigmask() 线程场景 ^eiDLxe7P

信号处置
进程收到信号后，自定义处理方式，核心函数sigaction()和signal() ^sOa8mCGD

#include <signal.h>
int sigaction(int sig, const struct sigaction *act, struct sigaction *oldact); ^5o6ptD2k

sig-要处置的信号（如SIGINT、SIGTERM,不能是SIGKILL/SIGSTOP）
act- 传入参数，指定信号的新处置方式（结构体）
oldact-输出参数，保存信号原来的处置方式（可设为NULL） ^nsIqlNh5

struct sigaction {
    void (*sa_handler)(int);//信号处理函数（SIG_DFL=默认，SIG_IGN=忽略，自定义）
    sigset_t sa_mask;//处理该信号时，要阻塞的其他信号集
    int sa_flags;//信号处置标志（如SA_RESTART:重启被中断的系统调用）
    void (*sa_sigaction)(int, siginfo_t *, void *);//替代sa_handler
} ^YPtyP9px

#include <signal.h>
void (*signal(int sig, void (*func)(int)))(int); ^y6RjNXr4

typedef void (*sighandler_t)(int);
sighandler_t signal(int sig, sighandler_t func); ^c4iFZN7a

进程与线程的核心差异
进程是”资源分配的最小单位“
线程是”cpu调度的最小单位“ ^lPhgnLJP

资源开销      大(独立地址空间、页表、文件描述符)      小（共享进程资源，仅独有栈/寄存器）

通信方式      需IPC(管道/消息队列/共享内存)           直接读写进程全局变量（共享地址空间）

切换成本      高（切换地址空间、刷新TLB）             低（仅切换寄存器/栈）

独立性         强（一个进程崩溃不影响其他）             弱（一个线程崩溃导致整个进程退出）

PID/TID     独有PID                                      共享进程PID,独有TID(线程ID) ^NYydr6Q4

进程 ^n6Qpu9C1

线程 ^XoKsU8x1

线程的优势（为什么用线程而非多进程）
资源利用率高：创建线程的开销仅为进程的1/10左右；
通信效率高：无需跨进程IPC,直接共享全局变量；
并发粒度细：可在一个进程内同时执行多个任务（如一个线程处理网络请求，一个线程处理计算）。 ^ycGjbCG6

线程的核心属性
-线程ID(pthread_t):进程内唯一，不同进程的TID可重复
-线程属性（pthread_attr_t）:如分离属性、栈大小、调度策略等
-线程状态：运行、终止、可连接（joinable）、分离（detached）

linux下查看线程的命令
ps -LF PID     查看指定进程的所有线程（L = 显示线程，f = 全格式）

top -H -p PID 实时查看指定进程的线程资源占用

pthread_self() 代码中获取当前线程的TID ^1jkQ4lNc

Threads核心API
线程创建              pthread_create()

线程终止              pthread_exit() pthread_cancel()

线程等待（连接）    pthread_join()

线程分离              pthread_detach()

获取线程ID           pthread_self()

线程属性初始化       pthread_attr_init()/pthread_attr_destroy() ^J4hKb3ya

线程的创建
pthread_create() ^sAevUevm

#include <pthread.h>
int pthread_create(pthread_t *restrict tid,
                   const pthread_attr_t *restrict attr,
                   void *(*start_routine)(void *),
                   void *restrict arg); ^A8BZX4GN

//输出参数，保存新创建线程ID(pthread_t类型) ^qS7z7wgn

·必须严格遵守 void *thread_func(void *arg)
·忘记链接pthread库：编译时不加-lpthread
·传递栈变量作为参数：线程入口函数执行时，栈变量可能已被销毁，
需用动态内存（malloc）
·主线程提前退出：主线程不调用pthread_join会直接退出，导致子线程被强制终止
·参数类型转换错误：void*转整数时，需先转long ^Gw6er0m9

//线程属性（如分离属性），NULL表示默认属性（可连接状态） ^XfjdGW2A

//线程入口函数（函数指针），格式为void *func(void *),返回值是
线程退出状态
//传递给线程入口函数的参数（void * 类型，可传递任意数据，
需手动类型转换） ^zK3LAn6m

线程终止的3种方式

    return   线程入口函数执行return,等价于pthread_exit(return值)
    
    pthread_exit(void *ret)  线程内部主动调用，终止当前线程，返回ret(可被pthread_join获取)

    pthread_cancel(pthread_t tid) 其他线程调用，请求终止指定线程（目标线程需响应取消点） ^TWVtJKnh

线程分离属性（detached）
核心概念
·默认情况下，线程是”可连接（joinable）“状态
-线程终止后，资源不会立即释放，需主线程调用pthread_join回收，否则会产生”僵尸线程“
·”分离（detached）“状态：线程终止后，资源由系统自动回收，无需调用pthread_join
·适合场景：无需获取线程返回值、不关心线程何时终止的场景（如后台日志线程）

分离属性的2种方式
方式1：创建线程时指定属性
方式2：线程内部调用pthread_detach ^wkQXG8EO

pthread_join
核心作用
-阻塞等待指定线程终止（若已终止，立即返回）
-回收线程资源（避免僵尸线程）
-获取线程的退出状态（返回值） ^Jv49xeFw

int pthread_join(pthread_t tid, void **retval); ^GU6Jzrql

要等待的线程ID ^o7JbxSHX

输出参数，存储线程的退出状态 ^HMZf8Zuf

线程同步
核心是解决多线程共享资源时的”数据竞争“问题
本质：控制多线程对共享资源的访问顺序 ^4OArtXm1

数据竞争的解决方案
用互斥量（Mutex）保护临界区，确保同一时间只有一个
线程能执行临界区代码 ^3sCcGDK0

互斥量Mutex解决同步问题
核心概念
互斥量（互斥锁）：本质是”锁“，保护临界区
核心规则
1.线程进入临界区前，必须加锁（pthread_mutex_lock）
2.线程退出临界区后，必须解锁 （pthread_mutex_unlock）
3.若锁已被其他线程持有，当前线程会阻塞，直到锁被释放 ^23Q2q3Sx

核心函数（静态初始化） ^hV1sfEOk

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int pthread_mutex_lock(pthread_mutex_t *mutex);

int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_mutex_destroy(pthread_mutex_t *mutex);

 ^QJWiaLku

静态初始化互斥量（最简单，全局/静态变量适用）

加锁（阻塞式，锁被占用则等待）

解锁（必须由加锁的线程调用）

销毁互斥量（释放资源） ^2I4Cuu4I

互斥量的关键避坑
1.锁必须配对：加锁必须解锁（即使临界区出错，也要用pthread_cleanup_push确保解锁）
2.避免死锁：
    ·不要嵌套锁（线程A持有锁1，想加锁2；线程B持有锁2，想加锁1）
    ·不要在临界区调用阻塞函数（如sleep）,延长锁持有时间
3.临界区尽量小：只保护必要的共享资源操作，减少线程阻塞时间 ^zWslupFL

动态初始化的互斥量
静态初始化仅适用于全局/静态变量，以下场景需动态初始化：
·互斥量是局部变量（栈上）或动态分配（堆上）
·需要自定义互斥量属性（如递归锁，错误检查锁） ^rufglsJO

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
-mutex:要初始化的互斥量指针
-attr:互斥量属性（NULL=默认属性，非递归锁） ^d3QlLqFz

读写锁（RWLock） ^Kw8hw5eu

核心：
互斥量的问题：无论”读“还是”写“，都独占锁，效率低
（比如100个线程读、1个线程写，互斥量会让读线程串行执行）

读写锁：区分”读操作“和”写操作“，规则更灵活
-读共享：多个线程可同时加”读锁“（无写锁时）
-写独占：只有一个线程能加”写锁“（此时无读锁/其他写锁）
-适用场景：读多写少（如配置文件读取、缓存查询） ^rhn5j0cY

读写锁核心函数 ^omeBg3rG

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

int pthread_rwlock_init(pthread_rwlock_t *rwlock,
const pthread_rwlockattr_t *attr);

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
 ^VXzlzIQx

//静态初始化读写锁

//动态初始化


//加读锁（共享）

//加写锁（独占）

//解锁（读/写锁通用）

//销毁读写锁 ^AwrbMjZY

读写锁rwlock避坑
1.读锁和写锁必须配对解锁，否则会导致死锁
2.写锁优先级高于读锁，若有写锁等待，新的读锁会阻塞，直到写锁释放
3.不要在持有读锁时尝试加写锁 ^lmovKV0J

条件变量（condition variable） ^X6W2M5Gp

核心问题：互斥量解决不了“等待条件”
互斥量只能保证临界区互斥，但无法解决“线程需要等待某个条件满足才能执行”的问题。比如
·生产者线程生产数据，消费者线程消费数据
·消费者没数据时，不能一直轮询（浪费CPU）,需要“等待”生产者生产；
·生产者生产后需要“唤醒”消费者 ^dJrwAkTr

条件变量：配合互斥量，实现线程间的“等待-唤醒”机制，核心是：
1、线程A等待某个条件，调用pthread_cond_wait,释放互斥量并阻塞
2、线程B满足条件后，调用pthread_cond_signal/broadcast,唤醒线程A;
3、线程A被唤醒后，重新获取互斥量，检查条件是否满足

 ^XTRpsYkn

核心属性：
·必须配合互斥量使用（避免等待和唤醒的竞态）
·不保存条件状态，只负责“唤醒”（被唤醒后必须重新检查条件）
·支持“单唤醒” （signal）和 “多唤醒”(broadcast) ^unLguMYd

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int pthread_cond_init(pthread_cond_t *cond, 
            const pthread_condattr_t *attr);

int pthread_cond_wait(pthread_cond_t *cond,
                     pthread_mutex_t *mutex);

int pthread_cond_signal(pthread_cond_t *cond);

int pthread_cond_broadcast(pthread_cond_t *cond);

int pthread_cond_destroy(pthread_cond_t *cond); ^1WcZbKPz

//静态初始化条件变量

//动态初始化 ^w6RqBdi7

//等待条件（释放mutex,阻塞；
被唤醒后重新加锁） ^CvTJjEiV

//唤醒一个等待该条件的线程 ^zXwwtwjR

//唤醒所有等待该条件的线程 ^vSmorwvk

//销毁条件变量 ^UAvnAGAN

虚假唤醒 ^bTfRwORD

线程调用pthread_cond_wait后，被唤醒但条件并未满足
（比如内核调度、信号中断、多个线程被唤醒但资源已被抢占） ^lz4UBUh3

避坑建议：
1.必须用while检查条件：这是解决虚假唤醒的唯一标准方法；
2.条件变量不保存状态：不要依赖“唤醒次数 = 条件满足次数”
3.互斥量必须配对:pthread_cond_wait必须在加锁后调用，唤醒后自动重新加锁 ^opJamefQ

同步机制                               核心作用                                适用场景                        关键注意事项
互斥量（Mutex）        互斥访问临界区，解决数据竞争        读写都少 / 读写均衡           锁配对、避免死锁、临界区尽量小

动态互斥量                初始化堆 / 局部变量的互斥量         非全局 / 静态互斥量           初始化后销毁，释放堆内存

读写锁（RWLock）       读共享、写独占                         读多写少（如配置 / 缓存）    写锁优先级高，读写解锁配对

条件变量                   线程间等待 - 唤醒，配合互斥量使用  生产者 - 消费者、任务等待    必须用 while 检查条件，解决虚假唤醒 ^9p6cbhgY

线程取消 ^iDRtPeVD

“可取消状态”（Cancel State）--能不能取消
可取消状态是线程的“开关”，决定线程是否允许接收取消请求：
PTHREAD_CANCEL_ENABLE(默认)：开关打开，线程能响应取消请求
PTHREAD_CANCEL_DISABLE:开关关闭，取消请求会被暂存，直到开关重新打开才处理

state:要设置的状态
oldstate:保存原来的状态（传NULL则不保存）
 ^EYGx4Fb1

”取消类型“（Cancel Type）  --什么时候响应取消
仅当取消状态为ENABLE时生效，分两种：
-PTHREAD_CANCEL_DEFERRED(默认)：
    延迟取消--线程只有到取消点才检查并响应取消请求
-PTHREAD_CANCEL_ASYNCHRONOUS:
    异步取消--线程随时可能被取消（无需等取消点），
慎用（容易导致资源泄漏） ^vyQZBQtT

int pthread_setcancelstate(int state,int *oldstate) ^8M2ojowI

int pthread_setcanceltype(int type, int *oldtype) ^oF8sF3p5

取消点
常见的默认取消点
·阻塞I/O:read()、write()、sleep()、usleep();
·线程同步：pthread_join()、pthread_cond_wait()
·主动设置：pthread_testcancel()(手动插入取消点) ^oZkk0HF2

清理函数
为什么需要清理函数？
线程被取消时，如果持有锁、申请了内存、打开了文件，
这些资源会因为线程突然退出而无法释放，导致泄漏
清理函数就是用来兜底，线程被取消时，自动执行清理
逻辑。
 ^LbmT8rJT

void pthread_cleanup_push(void (*handler)(void *), void *arg);
 ^D182ETy6

//注册清理函数：handler是函数指针，arg是传给handler的参数 ^KWJSx0bL

void pthread_cleanup_pop(int execute); ^TqOFa47t

//注册清理函数：
//execute=0 -> 只注销，不执行
//execute != 0 -> 注销并执行 ^9abRpj02

核心特性
1.栈式执行：先注册的后执行（后进先出），适合嵌套资源申请
2.执行时机
-线程被取消时(pthread_cancel)；
-线程调用pthread_exit()时；
-pthread_cleanup_pop(execute≠0)时
若线程通过return终止，清理函数不会执行 ^Xvy4fZGH

核心避坑：
1.必须成对使用：pthread_cleanup_push和pthread_cleanup_pop是宏，
展开后包含{}，必须在同一代码块成对出现，否则编译报错。
2.栈结构：清理函数按后进先出执行，需注意注册顺序
3.return不触发：线程用return终止时，清理函数不会执行，需用
pthread_exit()代替
4.重复释放：清理函数执行后，pthread_cleanup_pop若参数为1，
会执行函数，避免重复释放资源 ^65Hkj1Wo

进程通信 ^RyoUyc5J

管道（pipe）
核心：内核维护的单向字节流缓冲区
无名管道（pipe）和命名管道（FIFO）

-管道的本质
内核为两个进程建立的临时单向通信通道，底层是一块内核缓冲区：
·写进程通过”写端文件描述符“向缓冲区写入数据；
·读进程通过”读端文件描述符“从缓冲区读取数据；
·数据读取后会从缓冲区删除且只能读一次（字节流，无记录边界） ^a0kGkS7W

创建方式                   

亲缘关系要求 

           

文件系统可见性

生命周期


通信方向

核心函数 ^0FwApTAW

无名管道(pipe) ^2AELls2R

命名管道（FIFO） ^IAw93VCF

pipe()函数 ^kBaTiZNv

mkfifo()函数/命令行mkfifo文件名 ^rJOnbnld

仅适用于有亲缘关系的进程
（父子/兄弟） ^9A2kPrg0

适用于任意进程（无亲缘关系） ^w8oFS2SW

不可见（仅存在于内核） ^4siqyItH

可见（创建后生成FIFO文件,
类似普通文件） ^7iZ0Q92P

半双工（单向） ^njlc3piy

半双工（单向） ^GjKOgaio

pipe()、fork()、read()、write()  ^dL3hIuZh

mkfifo()、fork()、write()、read() ^zTwheX0q

随进程退出/
关闭所有文件描述符而销毁 ^1AtxipBg

随最后一个进程关闭
文件描述符而销毁
（FIFO文件需手动删除） ^jztZWkIE

-核心特点： ^lotFdxdr

1.单向通信： ^Ixx18A1e

2.阻塞特性： ^HvWy1fJm

3.字节流传输 ^ktHhmMcc

4.文件描述符继承 ^ctVscwQk

默认只能从读端读、写端写，双向通信需创建两个管道 ^pXp46GRg

·读端：管道为空，read()会阻塞，直到有数据/写端关闭
·写端：管道满时，write()会阻塞，直到有空间/读端关闭 ^fEKpcDMi

无数据边界，读取时需指定缓冲区大小，可能分多次读取 ^AjsYbFMB

无名管道依赖fork继承文件描述符
命名管道通过打开同一FIFO文件获取描述符 ^W6QKRC08

#include <unistd.h>
int pipe(int fd[2]) ^tLaxmEOD

//功能：创建无名管道，生成两个文件描述符
//参数：fd[2] -输出参数，fd[0] 读端，fd[1]写端
//返回值：成功0，失败-1 (设置errno) ^X89E42yW

核心函数 ^5OqSIidK

无名管道 ^9UOqkkQD

核心流程：
1.父进程调用pipe()创建管道，得到fd[0]读、fd[1]写
2.父进程调用fork()创建子进程，子进程继承两个文件描述符
3.确定通信方向（如父写子读）
·父进程关闭读端（fd[0]）,只保留写端（fd[1]）
·子进程关闭写端（fd[1]）,只保留读端（fd[0]）
4.父进程通过fd[1]写数据，子进程通过fd[0]读数据
5.通信完成后，关闭所有文件描述符
 ^5kvx7pmO

关键避坑
 ^cFUNQinN

1.关闭无用的文件描述符 ^jfAewCee

2.fork的时机 ^mb6XDhbm

3.数据长度 ^MkxBZzYV

4.阻塞特性 ^grzzy6i2

5.避免僵尸进程 ^jbs4A4Lj

父写子读时，父必须关闭读fd[0],子必须关闭写fd[1]
若父进程不关闭写端，子进程的read()会一直阻塞（认为还有数据） ^1NLXkqMV

必须先pipe再fork,不然没法继承管道描述符 ^qvBuloyG

write()写入的是字节数，read()读取时需要注意缓冲区大小，
且要手动添加字符串结束符'\0' ^X5tJ1V4U

管道为空时read()阻塞，满时write()阻塞（默认大小是4kb） ^IiM5Wzj2

父进程需用waitpid()等待子进程退出 ^WNx8bcbI

拓展
若需父子进程双向通信，需创建两个管道：
·管道1：父写->子读
·管道2：子写->父读 ^LugynPVT

代码框架 ^SiTnIh1c

int fd1[2],fd2[2];
pipe(fd1);//父写子读
pipe(fd2);//子写父读

//父进程：关闭fd1[0],fd2[1]（写fd1[1],读fd2[0]）
//子进程：关闭fd1[1],fd2[0]（读fd1[0],写fd2[1]） ^uG9AfCfM

命名管道（FIFO） ^rC3bsmCK

通过”文件系统可见的FIFO文件“实现任意进程间通信 ^XhPFr0cF

·FIFO文件只是”标识“，数据仍存储在内核缓冲区； ^dVuUJWrY

·多个进程可通过open()打开同一FIFO文件，获取读写描述符 ^F5JfkyR1

·FIFO文件需手动创建（mkfifo函数/命令），通信完成后需手动删除 ^f5gIHpVo

核心特点 ^9J9G1lGL

#include <sys/stat.h>
#include <fcntl.h>

int mkfifo(const char *pathname, mode_t mode);

int open(const char *pathname, int flags); ^mKbzbXUM

//1.创建FIFO文件
//参数：
//      pathname - FIFO文件路径（如”./my_fifo“）
//      mode - 文件权限（如0664，同普通文件）
//  返回值：成功0,失败-1（已存在则errno=EEXIST） ^ZG0sGCMk

//2.打开FIFO文件（与普通文件open一致，但有阻塞特性）
//阻塞规则：
//-只读打开（O_RDONLY）:阻塞直到有进程以写方式打开该FIFO
//-只写打开（O_WRONLY）:阻塞直到有进程以读方式打开该FIFO
//-非阻塞打开（O_NONBLOCK）:不阻塞，直接返回（无对应进程则失败） ^HTGXlQlL

核心函数 ^785z017m

核心流程 ^vp48Fb2p

进程A(读进程) ^wpVP0EG9

进程B(写进程) ^Bpml4qQ5

调用mkfifo()
创建FIFO文件 ^qC4S6vwe

以O_RDONLY打开FIFO,
阻塞等待写进程连接
 ^Ecmok4Ye

读数据，完成后关闭描述
符，删除FIFO文件 ^fzoLcywY

以O_WRONLY打开同一FIFO,
阻塞等待读进程连接 ^A6pPXMjN

写数据，完成后关闭描述符 ^X6tmvxSm

关键避坑 ^JvpETmIZ

1.路径一致性 ^6VFSgLBe

2.打开顺序与阻塞 ^WafPesjf

3.FIFO文件删除 ^6MX8CP5C

4.多进程读写 ^2TNh8scD

5.权限问题 ^NGWYGLzY

mkfifo的mode参数需保证读/写进程有对应权限（如0664） ^ToZeUDGL

通信完成后建议删除，避免残留文件 ^Fb0uF6mJ

多个进程可同时写FIFO,
但需注意数据拼接
（无锁时可能出现数据错乱） ^DtyWhB30

-先启动读进程（创建FIFO）,再启动写进程
-若需非阻塞打开，在open时加O_NONBLOCK ^vHn63Ifc

读/写进程的FIFO路径必须完全一致 ^ZLUxP5zM

局限性 ^UDr6DuiC

半双工（双向需要两个管道）
只能传输字节流（无结构化数据）
无数据同步机制（多进程写易错乱）
命名管道依赖文件系统，需处理文件残留问题 ^kuudF2gF

消息队列存储”带类型/优先级的消息“,而非字节流； ^ygH52KWy

数据写入队列后持久化（内核中），直到被读取/手动删除； ^cDQKsP9i

System V是传统接口（依赖键值）,POSIX是现代接口（依赖文件路径），功能更丰富 ^vkgWYv9X

ftok ^R67HW9eo

msgget ^vyk3elxN

msgsnd ^iNwkwT65

msgrcv ^aSdMDTMt

msgctl ^dYdFPVoS

//功能：将文件路径+项目id转换为唯一键值（用于标识消息队列）
//参数:
//   pathname:存在且可访问的文件路径（如“./test.txt”）;
//   proj_id:项目ID(1个字节，通常用ASCII字符，如‘a');
//返回值：成功返回key_t(键值)，失败返回-1 ^4GMUiDg7

#include <sys/ipc.h>
key_t ftok(const char *pathname, int proj_id); ^tMgV7mFN

生成唯一键值 ^hwa3uHrW

#include <sys/msg.h>
int msgget(key_t key, int msgflg); ^6jLvN8h0

//功能；从消息队列接收指定类型的消息
//参数：
//   msqid:消息队列ID
//   msgp:接收消息的结构体指针
//   msgsz:消息正文最大长度
//   msgtyp:消息类型（核心！）：
//        - 0:接收队列中第一条消息（区分类型）
//        - >0:接收队列中类型为msgtyp的第一条消息
//        - <0:接收队列中类型<=|msgtyp|的最小类型第一条消息
//   msgflg:接收标志（0：阻塞；IPC_NOWAIT:非阻塞，无消息则返回）
//返回值：成功返回接收的正文长度，失败-1
 ^flXQz8me

//功能：创建新消息队列，或获取已存在的消息队列ID
//参数：
//    key: ftok生成的键值
//     （或IPC_PRIVATE:创建私有队列，仅亲缘进程可用）
//    msgflg:标志位（权限+创建标志），如IPC_CREAT | 0664;
//             -IPC_CREAT:不存在则创建
//             -IPC_EXCL:与IPC_CREAT配合，队列已存在则返回错误
//返回值：成功返回消息队列ID(msqid),失败返回-1 ^MbJWhMKI

创建/获取消息队列 ^uLgltbBv

int msgsnd(int msqid
         , const void *msgp
         , size_t msgsz
         , int msgflg); ^QHKxPdGu

//功能：向消息队列发送一条消息
//参数：
//  msqid:消息队列ID
//  msgp:消息队列指针（自定义，首成员必须是long型消息类型）
//  msgsz:消息正文长度（不含消息类型）
//  msgflg:发送标志（0：阻塞；IPC_NOWAIT:非阻塞，队列满则立即返回）
//返回值：成功0，失败-1 ^xlMivcKi

发送消息 ^H3SO0r2e

ssize_t msgrcv(int msqid
               ,void *msgp
               ,size_t msgsz
               ,long msgtyp
               ,int msgflg); ^2lROmvMz

接收消息 ^ryQviLeT

int msgctl(int msqid
         , int cmd
         , struct msqid_ds *buf); ^GRZJWoQJ

//功能：删除消息队列、获取/设置队列属性
//参数：
//     msqid:消息队列ID
//     cmd: 操作命令：
//             -IPC_RMID:删除消息队列（最常用）
//             -IPC_STAT:获取队列属性
//             -IPC_SET:设置队列属性
//      buf:队列属性结构体指针（IPC_RMID时传NULL）
//返回值：成功0，失败-1 ^8qw67qmH

控制消息队列 ^0gPRufC8

typedef struct {
    long msg_type;
    char msg_text[1024];
}MsgBuf; ^2YpAcTix

消息结构体 ^tKJ9UKQT

//必须是long型，>=1(类型0无效) ^cIVyRB56

//消息正文（可替换为任意结构化数据） ^tu0fEafz

System V 消息队列 ^CY8Un72N

关键避坑 ^VBEv1zJ7

1.ftok键值生成 ^tLhT6i8n

2.消息类型规则 ^Lw6Wvv4B

3.消息长度 ^OwuPErUx

4.队列清理 ^NqobAjqy

5.权限问题 ^RHUgFA25

-必须保证MSG_PATH文件存在并可访问；
-同一文件+同一PROJ_ID生成的键值唯一，不同进程需用相同参数 ^LXepkoSO

-消息类型必须>=1(0无效)
-msgrcv的msgtyp参数决定接收规则，按需选择 ^wKWzYSjc

-msgsnd的msgsz是“正文长度”，不含msg_type
-msgrcv接收后需手动加'\0',避免字符串乱码 ^p8HB7ddC

-用完必须用msgctl(IPC_RMID)删除，否则消息队列会残留
（可通过ipcs -q查看，ipcrm -q msqid 手动删除） ^kch9VVA3

msgget的权限（0664）需保证收发进程都有读写权限 ^8WWUBsdr

posix消息队列 ^oW3oKmgp

核心优势 ^A5jgSORg

-支持显示优先级（0-31，数值越高优先级越高） ^PTKXIuJL

-接口类似文件操作（open/close/write/read），学习成本低 ^TYpWUx0v

-支持非阻塞模式、消息大小/队列长度自定义 ^K10KZKIS

-可通过mq_notify实现“消息到达通知”（无需轮询） ^Rpilao8p

mq_open ^N2FKHFvJ

mq_send ^rxTtpU96

mq_receive ^xWreqnAo

mq_close ^YpbTdA2T

mq_unlink ^ympHTDpC

struct mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
} ^hpBKPipI

#include <mqueue.h>
mqd_t mq_open(const char *name
             ,int oflag
             ,mode_t mode
             ,const struct mq_attr *attr); ^AQHkJnPh

//功能：创建/打开POSIX消息队列
//参数：
//    name:队列名（必须以/开头，如“/my_mq”,全局唯一）
//    oflag:打开标志：
//           -O_RDONLY:只读；O_WRONLY:只写；O_RDWR:读写
//           -O_CREAT:不存在则创建；O_EXCL:与O_CREAT配合，已存在则失败
//           -O_NONBLOCK: 非阻塞模式
//     mode:创建队列时的权限（如0664，仅O_CREAT时有效）
//     attr:队列属性（NULL=默认属性）
// 返回值：成功返回消息队列描述符（mqd_t）,失败返回（mqd_t）-1  ^DYeb7LdZ

打开/创建消息队列 ^wLkb1WIl

int mq_send(mqd_t mqdes
           ,const char *msg_ptr
           ,size_t msg_len
           ,unsigned int msg_prio); ^2pfTq93V

//功能：向POSIX消息队列发送给带优先级的消息
//参数：
// mqdes:消息队列描述符
// msg_ptr:消息正文指针
// msg_len:消息正文长度（<=队列的mq_msgsize属性）
// msg_prio:消息优先级（0-31,数值越高优先级越高）
//返回值：成功0，失败1 ^ifeCBObG

ssize_t mq_receive(
     mqd_t mqdes
    ,char *msg_ptr
    ,size_t msg_len
    ,unsigned int *msg_prio
); ^Q7zIa4JB

发送消息 ^gsT1mLfy

功能：从POSIX消息队列接收优先级最高的消息
//参数：
//  mqdes:消息队列描述符
//  msg_ptr:接收消息的缓冲区指针
//  msg_len:缓冲区大小（必须>=队列的mq_msgsize属性）
//  msg_prio:输出参数，存储接收消息的优先级（NULL则忽略）
//返回值：成功返回接收的字节数，失败-1 ^Xe9UwMO8

接收消息 ^EHJFGC4R

int mqclose(mqd_t mqdes); ^DPltDsp0

//功能：关闭消息队列描述符（进程不再使用，但队列仍存在）
//参数：mqdes:消息队列描述符
//返回值：成功0，失败-1
 ^HgOzMdY8

关闭消息队列 ^Sn0JT8g4

int mq_unlink(const char *name); ^chlkdawr

//功能：删除消息队列（内核中销毁，需确保所有进程已关闭）
//参数：name :队列名（如“/my_mq”）
//返回值：成功0，失败-1 ^Ipl8aDsK

消息队列属性结构体 ^z2Ajty2G

删除消息队列 ^26WLirdS

//队列标志（0=阻塞；O_NONBLOCK=非阻塞） ^ST5ZXcfh

//队列最大消息数（默认通常10） ^MVhNbKYp

//单条消息最大字节数（默认通常8192） ^IUPny3jy

//当前队列中的消息数（只读，无法设置） ^Ei50TyB1

## Element Links
uG9AfCfM: [[写fd1[1],读fd2[0]]]

## Embedded Files
fb1536895c3674b1364febfa1ebfef6b89ac7763: [[Pasted Image 20251209100038_660.png]]

7c82720b73013b48e2cc063662fe80573cda8cc6: [[Pasted Image 20251209100746_067.png]]

494ba6122023dddbedecf1eafedb8b781c917592: [[Pasted Image 20251209103718_109.png]]

c9c863bc116629cf2e60f65397a0280a9292ae0c: [[Pasted Image 20251209111631_702.png]]

1960eed1519a1043b169f0c1fd56e5cb2b81f2ad: [[Pasted Image 20251209154115_755.png]]

7c46d7ffac7b6cbdb56b1081c88a330266aa10af: [[Pasted Image 20251209154233_088.png]]

721e4083ad252c8a919bcccadd9bf1f43883735f: [[Pasted Image 20251211202758_980.png]]

e073c977f08968f45691687b108f94b09a6fe533: [[Pasted Image 20251212162934_017.png]]

%%
## Drawing
```compressed-json
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

kVyaZMxOumVBX5Fg2XbERmGmwCZnlWUEAwatmDSgwRTYDt5konjJRXwfQWVJTYFwGWcvqoBUixSgnholeWcUPB5IYa+1IQ4NObFRaFlpUUBBWpZyOo15Ro5+AC/9voA9ACvgMFFRlk9sIDQk1pHBcXJkEYqNNlkjcpm5Pj0Go4t5E2yVNiQtJSJXnFaFO5FQDEgMdGeU0UjGQBFfGVJ5XzFSKn7ucJllwQvAIgxMgnldCDS8I6PWdMhS/DSuQ2xP

QVSiH0F1DhE+MrFlVaRgC5lVmWOBe+8dmVankv41ACJZT24QELUAG/lt8VpZd/li/jUAJ6yt8XdAEpmTkAHCPKlFmWA5EAVwQXQmJ/l2mWgFQv4v+VZ0vplaBWBQIAVKWVWZSAVABUQFSAl0BWoALAVXmWYxUqxscgN5ftEAokQxaGlUMUe+RLlISrKhEZl7+XIFVplcWXYFc5AGBU+vFgVABWIFSZlXBUwFUQVriUkFWQV5mVZZWV5I1n0Bah4p

AD4QGYAgEDnMbFhO0KyNFhczeRrFDwFUHLV6JoY1EmQFiTYY2Cu8OGBflb9qv7OY0VuRTn5HMV1oTxl16VTMVYZrSWLRQt5Q2Vp5UeJIUXM/OGePbAEPgfKbMm02HtCUmU/pVHCCmWBQWQ4rFhKxWXlAslS0fvFeGiRFed4uzntZfpYTCUoZTcZywVgfugA0RVDqW25EkFCOGEQ0FTAVBZIehaJ9D7lIhR+gTiMHlzyGfVKxThE5KDBZ5w7QgfUd

HB7/mmxWHLN0mYVdyriiZNF3g7WFdrpH/n8ZXwpgmXVmZ0lcrYrAGJJkEUYzlk2wRwTIUFlldGBwEiq6XH+FUbUgRWVXthMphji2WEVw5F2BWZlIwUoFZwVtATYjpgpxADOZdDcXqUgUtLgT3CaAH3U8BX5DrfFGxUcFRjA2xVysbsV+xWI3LFlpQhWgM9wpxXMgD5lj1QBOpYMe9RniFKeMP7CRU8B/gVoZe3lISrrFeaxmxU3FTQEOxX6AHsV3

+UI3P1cTxV6iscVbxVqRVIVGRXvQbLAX9bhzMcAisD6APnemLn7BaoVo+U05nmo/yiT5e3KJaERWWecjRAHmNCU69gNFVAsGy5dZRqZwXEJ5V0Vu+V3pfvlinmH5SDEsZmxcUPASdqdoDE+F+XMOfqaXhlTuc350IULZUXllgWucE4WoUG1hb7sb7l+JJHgCgB2drKC8RLy5ciliuUepSHFuxVoAAzs9xg7Jc2lncWd4N4gyABKlZOCYGA4pFKFJ

iXdpYElZ+D1PJHgGpUAimalS/gtpRyAV07IAOqVsXialV2lqABvFcgALpUyJYpyYGCmla+A3iBOkGN2sDww5U7l24XuYYqVyTDKlaqVPpV+lUml2pVTpejlO8VQJfqVqACGlXcYxpXhBC2lZpXVABaVSZVWlTaVsqXQpZ3FjpXIAM6VvpWulf6V7pU1lV6VqZWNlYv4gZXBlXbFoZXhlZGV0ZWAQMPFrqVxlX6lQMUJykIi45UTlRFZzeXoeSwlp

oFYefP59HGNQZaVsoIqlaF5bZUo5VAlOpXHZTmVMJUGlX4wRpV2Ja/FvZWllcuVsXjWlbaVh5WhxTWVUhB1lRHgLpWXlQXFLZX1POuVUCUBlX3UQZUNlSGVYZWBJSWVUZW13LGVPOU4ZVUAKQDKAOclfdRntF7lnUzt2VucahQjZnhYtMTUxVSwEYHLEO7Uh8ZHmCesllG1dCMgk0xsZY3ZzJVBcenRbJUfBbelXwVclctFSnlH5aDetdlDwSUqE

soO6bk4BvnS5np5WJACibMVfwTzFV0B2EzdqgKJz+XsJCSokGXoBRAA/FXYZW9RgggBZY3lfxX+Bi3lKlnhpSkVQlXEqAJV6RV0BWFpy5nQQCRA2ADIWP8Fg+UUOGVlahXHBcAWWjgVFV+6q6UauKQ8RvCdBTcJIvHauEVk4lXlZLFem+UbubxlthUcWfYVpYxLRX5ZMynONCsA6H6uFRahJOSbAv5sNfl8fkpqrobSxVKVssVHRbbuj/mJvqtlH

YnQrqeA2XynXI8Vo8howCIV0NingJAagUDksT35F3D9ADIhI0g/kes8r4CYBcjhzIC0Rf/SCVUtfPtcl3A8vM5AaVUXcAhAmVXOQNlVmAW5VQZA+VUHwIVVwbzFVcoApVU0LkDF9kU+1NNMQuVCRX4FYuVt5eVFyOqVVTl81VUpVfNA9VUZVWjALVXpVXlV8fldVdeAPVV9VZaez+Rcoe25QjhQAEXk4sErgIK4xF6C+bx5H/qoqhQ4s4jA0DVl5

wXvsBfJKcixVDCoROSzafoZcRUB6XHlmplEVdqZ/WULRW5VjhWp5cumKwBPScMVwbBzoNCioMFrKV4V0mWxFBFGjt5m+cH4HFVRmlMVLlihQVKCGdx4aOjVADyo+QFocRVE+NOVSXlhZXOVbCUhKljV6dwgOdgAG+njVK+GN04h+Si4kWj2ydz8W6iziMkQt1XFJdDVD84Icr20aLjfodS5KPzS+dFR+FUHCQep0nml2UBFf1XyeQDVv/kYmSsAW

D6g1c5BR9AgNrL+CUkmCVhcb1mjJbt50pVyuYHAiKYzibxV72Za5U9l3CDnSNX4oUA/0ikAvCBQ4gVJSgCG1UTlxtWm1ebVltV/ibOsG9SqDAkVouWiRQGZ4kUycrbVygCDcibV8QBm1RPoFtVW1SA5BuApAArqkeQD5SH56/64OAkFFGWD8C/6Pp72ohUVNkWEgYMilVpZyhz+fNXjeRJ500XlBTzF3RUl+Snl0tWrRXTJ1FWNsr6elnAQ8lf8V

7mmYdCoJNhSNPJlkVUqXoTkgmIKlQoAF8X1JLFY7fjZkMW5O2G/Zl3VoFA91X3V3rlPYZk0YdYw/oBJGHnE1RFlz/Gd1YolZYTd1c2Fo9U+ucNZ6JUUFHCAkECJAKiGC6DHhR8Zd07y+LP0nCJIqhc2kEYH1EHlr4XHnLcmsQV/2PiqzMVO+Qb01BXSactmrajtqDFxl0kGLuy5BDYS1b0VMam3ObyVScmJER8eRODU1JDV4VlTZZTUhaiz3gjVV

ThI1ci+O6gAAff8z7nY3sUwhPlZAKd5B9YiVaB5EADoNfoAmDWKVZDZErn+ZQ3lfHTu1V9RQJWMFW1ZpJB4NQQ12DVO4SFpylV7Vdy4wEBaxPQA8QBGAExAuwUlZa3wdsBbZCZ5naAnBY0BLujSBLwIsriYzvr6WahItAWW1dEP1T7+vLaYgULVTNnfVSzZ4tWuVZLV6vlOFUDVM1n8WWp5r6FkhlApfMlF/mbksdhyjs3Vi2W99GzgdjF28PsZ/

niHGXY153gtmDGI1HjkNbkx41XAlZNVISoPGUBVVICAQKL05wBaSrvGB9U8fCusN7kCNfo2YDYG6B3C+Dw2lGJ+sDbmDL5UCfwEwWsMPHqvdASIRjV4OanRLJWEVSyJP1VqNZy5DhWaNYDVic4rADfZ8tXVoGt0V2nc0c58UilGwOfIEVlsVYjVLdXIlGzga6zlqKFB3RikRTd54iQUobKYXTVacj01B6TUsJwo1UIE1Tj5abnkBchZRkB9NTCA3

TXtkCA5QkoJzHzCcwBiSQSVlEmqDMsCknQdphPlojWXxAYysyJn+V2w6KFTFXrBVOEOlGk1wgi51J9VrJW5Nao1JFUDZWRVHlW1BYx0KwCGWeU1TfBVzD3oUCkxaqTByLSB+rppjTVwNc015Ehs4KcWGy761UGZL2X3HB6ZULUsqJk0wzXDCH2MrjWkBZoRYkVUUZC16iXQtT416AALgBQAQgAeIL2AsNhaVQSVCcqADJbY+ypf+nmoFHjO8Ei0S

HRzrFRZsQV+cNTx4f4uWUxZJzn51dvlzlWXOeo1f9X6mb8FLzXzKb5ValRG6Hz4YUxAjoSZb34yPB2U5XTmNTKVljWaiG2MhDrtiSEZSGnRQFKC+6GCVWq1nFAatWOZyLUiRai1XtXotfggWrU6tTQFgx6ZKaNZTUSFgIrAdgAwgdnehPFWDsUahhaqbIbwUPyktTnOrRC5aI+FH6FJHF+hmFWqmZk16pkEVdmxotXK+fc1v9Ul1eoFImVoqRXVm

ipkhor+DDnNVMM+X56quEYYmKFxReYFwLVGeTkYmTjRURC1+CDlQLKCEk7EYUW12PjSOcwlRNUn4fOVSIqFtbF4xbXYtT1s9QDk6adAZECWSSeFN/DNqkqZzrWSdNLC86I0tdTYnrXEicsQmWgifkKwqi5nGRL5rAHr5fHhwtUImU0lFsqBDqRVFdkH5f0VammfQcxOR9COKIYJ2lQB4R2yxRqWxNjpGbWoRVm1+3m+VCRw9i75tVUAGlmCVde1u

rUpuSVFMlXJFTEpEgC3tWa1GSk6vjIVTUQRYcQo0ICRBXnBwTW87vGA2mp7wi612zVCSKCQ4kCxNfehZ5zx2a7YJHATNvrBflLXNTk1fEleWUXVVQWPNTUF/LVf9CsAl6mxtaLm+sDbhiCFxthBVZflyRju2BKVgLWF5c5ioLUo1aFBzgDKUPkkXeDivB4g3uD1AJWEm96XGJ6F1K7AapWEITDAauclC4A9sd4gaaVpEiCS9TKAAB9uYMjDzoJVD

HVKUEx1HIAsdWx1HHW6kFx1diw8deqQfHUCdb/2wnXVAKJ1QJLpElvybiBSdTJ1d7VIZdPVs5VVtSTVd7JydQp1SnUf6ip1anW0kBp1WnXqkIJ1unX6dcCS5kCSddJ1tl5KVebOzDXBEBQAVs5poRyA/wiVSgSVIUhktRZwCv5wzB5cnkn9tdfJAu6eSEMg05ZnZJeZ+WHIdSG187V2ar9eEbWYdT8FgsUaae81bg6UCDsMiXFsYqB2t9KGGBrVB

eVa1bI6bOD7rqEVkK5FES/lzgAvZcpQAdUYDE7VushIFfQA6VmuJWGQdHZsdvcc3CBmLPwgkpCAAJdGTX4ddUpQXXUh1RNArdquBf11ICVDdXtII3UsqGN1E3XTdeW1iRWUNbJVz7XoAO116iWddabVC3W9dct1A3V3xfAAa3UbdVt1U3UgOXAAiQBd1McAQeQTOSRlKPxdtZs1xaAdpmQkiXV0tUO1IwQ7rDRZmzTh+AyVu6nHOQQ5k3mctYnld

hUFNf9VRTWl1SJlg2n4ddmJn/JU2OeJQRkptVZwKhQzwVR19XWoJmzgcILR+oMFUtFLddZlV3VnxZbgaZDUJTR232U5VaeAF3VEgNCYbHbUMW0sZuyf4VPhaYQ74TrZ0eBNfhpllPVGANT1tPXwEgBuDPUIQEz1jgWs9YZ+HPUH4aPh3PVD4bz18FlJFZM1CjnFMOT10WWC9cL1FOV09WL1rVWM9S4AfXXS9c5ysvVf4Qr1WzpK9Q210IAn6FcAw

EA5pSWxg+UqwV91/059YFD8KpoecHs104g1wZOIhHBX+UnRQalZdbCpobV9Zfk1w8xtJZG1s1FrtVEFJXVzKFfECfwv/lNlLfAWGMCZsrU0dWe10mxyidhFkOzOAG4gOCGV0MMF4JXHleFAP1n2Cm+5hGD/WYYsO9EERUpEisCyEtwgBEWkAPg1zgCKwIbFm8WoADQxzB459Xn1KlAF9SW4RfUl9SyoZfUV9S8sVfVwALgizeC19TIS9fVj9Y31E

/Wt9WdIHfXK9ft1T7VpeRIAXfX59WsFhfU/lRGV0EID9UP1f8GV9QRQ1fUT9XX1DfVN9S31XqXt9eF569VMNZkV3LhXtMKA4JbMAF5+UDnT9Oi4wHXdtT91s4hkhnw1mTiWcCguj4XnbrFU8KI5aBP5Q1GB9SLVOXUzpon+DzXLtdyVq7Uy1cbpujXGYho2sqD0VVf8PzXMOcaIGzSG6rA11HUNdZi4sfzN0alF0K7XRXck5uX1Wd1ZaUD3kOZAQ

zoFBmssUYS9XkjFh5AXsUNZVA00DWZAdA1qgowNu3Ue1Qa1qXn4+eMFffnkDWwN+STUDbQN9A08Df51wt4qVah4bADCgLUAK0L6ABzCSppeSOl0i9DKuMDBpNktYRiM+3RCuQnItjieSM0xqy7zyLNoKpm89iouI+SC1ZxlOyhv1R2oUwJXpZ0VxFXodcnlBXUCxfbKKwAwGRqRMrgXNom1uoglUjgGNmIP8HNl8ikRVRY10MwUCOR1iGHBGegua

UWVsKwAmACENc4FhQhLjJK0SQ1ReZ4oG9BWDZJVuSYzlZW1vmkglXey8Q1pDfQ1LbnmtR+1sg1NRCRAKwD/CMoACZizgEQBTqlPZoS5MZL2ok355kUU8X7AgulVfkW8J6hkPC7489DxVHI1/LCpPsXoow1VzBYV+DkTeQr5ZzlQDfm2eXU8tRH1fWky1fMZJXVdBpCmRvn5XBKVFBbkPDh++0Uyxb0FT7STZoLuiAVrZWlFCuAnYgqmlw0xFUN5x

jAqGHcNOhR6tYCV7jVUNRm5zTry4NcN0g0WtZ+1Qjjv6iuAmuBCAExAhllNDeO8LQ3o3sjEe5yjCU/A/nAmlLBKhE5QjNTmmM726P2qKPwcsOrwaI3I4BANc7W9Zc0lv1WLDW4ND6XDZViZqPVb0sOuMjzQoh+eFpnWYh/6RsGp9QQNHZQ5mKcNcVXZ9cV4RhJWBublFd7jmrVAWnKAAFGxZoJWBnyNnfWsjYYS7I0pAJyNDtG8jfyNfAaCjZk0W

age6m9OlvRKtcFlFnX5DfDZTBU2dcKNoo3ijdyNfI0CjWaCN/UBdXf1wRDNQNBAj/XmjPUFRlmdlLgF47CL8Fiom7qADE8qFu6KDFzRQviPoTPYMUUj0iiNznC9YQqN2uTsxVMNedVb5U5VsPUuVfD1GjVl+cU1FQErAMjRJXULbEm0TflrKX4NWVITYJwwWXR0jYT1RVlGwLFVKrVxUc4Ar3lcPpWEDOxgYHvRCgBPjAgAUGDqvn6EKkhuJIAAZ

tqAAAZyJoK0UE1++Y2cPoWNnSwljWWNFY2pjlWNXHC1jQ2NgSxNjfo60EZg0KsUI43Q1WM1FYWqjeLl1DXq9S2NbY3FjWTEpY2zjOWNL449jYJg3CD1jY2NIDmsCikAK4AGIFCcUQUgjS3kRhhBcN+6kN4v8qpsvWAh4Vt5wRTh4fywfWDVENB0l9AzBEc0b7DTIm+NTflKNYoJqHVHWRyVS7X0qmdZnlVxlIqUvImLSN+6EUUJja2Z3TFXxAExc

inWYfflRw1FWWQ4KmXMjdimzgDFeG6ofiRSghQSCgCygvOhhmRNfhhN0qhYTZxQOE14TZECBE0HpHKNPo0sWIqNIpXKjWNVntUCDd7VL9lETcqoFKgkTWRNsXj4Te8kIDmbxmyAuABsAIkAZLZExQo4zQ1aDEb608R+Oq/63QQouGD8kVSGONM5n8yOeBeZfWHqoaiNo43vjVdyL9XEydk12XU4jQu19y74jXAN5FU8lTNkKwDvmSSNAUb8FOOi4

DWG+dVwOw1ETCkMYVXzZWENcrURDVexV5gClpe1a/U70foAisBvCEUiTV4wAFGQaZBSgqOQgAB98Qos7KYCIPzGnfV+TQFNtUFfQMyAIU2RkGFNnFCRTdFNHfZxTbKNxHg0TfKNM8ETjRW1reUeNeqNpSbOAAlNgU3JTalN6U2ZTfIsMU38IDlNDbXFoqdAjrSnQIPQqg05ZK6pBLgm3GMR2DowOfIEMgFtya454DAu6PeFN8LJGM5F6qFLFG+NG

I01ZHIFpQUctcGN7JVw9WH1hTURjUj1R+V8WSV12wLH0tsNJHXiiRQWexSsWLFFvhnC4fA18/Bj/H5UWEVmed35AU170b1e901kxMP5c9D5TTRNn0l0FQ+1uPmGtQi5h7BPTTkAIDmkAJgAzUCyALRAP7BKmv8CssoouF6GyWibuq2g2jhdFifSM8F6DFnYbtqEVMsMGXW89p46vo2+jXnOxQXyBdD1y03ODX+NsA0ATTc5PLkvNQPBVk30lpJ0T

ormYh3kwbh26H3ptXW2mQT1nDbJGLYOZxY+TeQMAU1hANQFyQ08zeyO/M0ZDa3ZmbSzTZpNbMiKzoxN/A1PPnJV/k1Cze1o6SnavrtVRo1KjIjRznQcACRAnPlHjVLOb8DX4mx42g3eVCGe5tQUeKo4TvhzEdhVbvBlKvKgeWFYzbXJLvmQ9daa+fmEzTYVIY3ctWGNvLWATc81OHWBWXd+7y4lyVIFiXGoeTmKE6KpEOKJ+PVuTWn1IIS2UqFB8

s2pmF8AjACPTTDYVUAJzSNojvkeUrUlRAVSzZDFqGWvDRGlf03JzWIABWUjaErNmAFAlpUNQjjQQA0WHDgrmRDNP+Sq8MxY/IwkcHucIEaSnoEIdSpKjXoMqhhMZUvlwioG6LRNfo2wLmbBz/mkjK/5HRXvBXk14bXGTWTN3LlATS81l1kABQzJIV7meIm+h0oFicvID/KxWcaRBw0ITZY10kCIcoNR3M0FzWWNSc0nzed46vTizbNN+NXZzfQVu

c0Hdav1gs1nzV8NFQ2Bddlio+x5CWGY73VOqcp6fDVS8ZygcglmFtH5+agAAWeoaIxaNlUa2myDBEZYI65MKTCqEs0L/sPNrlmjzc7NMw0zRQZNuXUwDfl1Jk1PNdh1UQgrANzZ1M0J2qoMLRCrzR9sr0bSZWflTnwuTaENhw17zdq2XkixzQFNY2pnaIJV8s3MLUpAMRVl5jjNtE3N2Z9N0lXfTcxNRrXTlEwtnOosLc/NKs0YlVUAkgBwABQoS

7wWgBDNdjGG6IB2GJCk5H46GJBZaBQIGyoHmDtEgclzAgJyyI21zJ46Wk1jjZ9+js3afO0VLs1ODZPNLg175dgtWHWCxTXZwDXALtnE1EikLXfiC7m0vuWYj6h49Ue1v6UntZ3okQ2LfDPBR82zVfLNhRJzVYFARBUBTbSxhTypVXSyNhoBTVfox4GYBU1VTkBRLdEap8UDIKktqADpLVQujfWnxZAaIbzuYaEtAU3hLbVVaS3xLfLNMS3ZLektS

S09+TUtlS2JLZktB0ANLQ/QCS3MUiIAKAWFLfC1B5zwLYe+k9UkUdLNBomCLb9NJS0FEquSES11VY0toLwKsa0tygDtLXUtKS1xLW0t8s0oBVktyy3zLfLNeS1dLZS8DbUkQHhl0ICtrPgCnU2W6HqUteh+bPRNpwV4ia3wFDgVGPRwj4VVGARZKbI3Kgu52rh4iQPNOM1BGW0V4zFv+fKRxM2rTWT84Y0/+VG1R+XUOYQtBeitEFvQ7t5YBlSNb

ihWBcY4+w3hVbQtHk0TYL9xZ0UPvP5N3MDcwAW4/k33pvLNLrHWsVKxgrFKZgcI0hlGvCSthLGOsfgwJK17XAcVpS0TLS/aCWbPRRitisBYrQgAOK2KwHit/01g3ORFz3DErVwVpK20sRStDrHCsdStAq20rclVYS0MrfF6KTFW6IPNfo2jNTfNX00TNWi1v024RZitSDrsretcuK1EsdytCkUVuPytBYKCreStAq2UraKtCAA0rcu4Yy3hLYytk

mYgOUSilEDHAIBAxACVGQ/RhklkPOiWZ42nBtLKR1IG9KXYu3SRXn2uWTi1GcdoqBHUuY54u0LojZpNa+XXmUphek1B9XMN8M566Qj1G00grbyVxWXIDW7KH2nU2HZNi9gD8GbY4zbfwkTB281IrbvNKK1PqVVGR821hWBlUnZQ+Z+Ab7kblW8lgrEfldvu3xpKUKl4CgA4lIAALJoKhWmQ/HHRGorAeZDUANqCaSwmJWSt0QDIAFJ2ZTyFle6VV

ilgCZBAyAAe8RokCfH4aQutsfHLrb7xpCjIAGqCD5Wl5K2l3uDtpSyofkAbrZalWKU+8balzUB4pYSl5UG7ravZRfHX2WgAbqghxVs4eaWygsqqg1nYcUyC561wpU6QgGBQ4naVvdoulQPazGhD2txkbHGZhW+5XUAtMpytqOw+pdBtyRKqhEAc8OU1rTiUda0NravFKHHNrbKCra3KUB2t3a29rf2t/k1DrSOt6pBjrbSxk604lNOtt63uKbi2i

60qghutqGmLrWssG62gCVutO62vla/F361tpQilHaW+QCetvaVnrfutl62p7Nwg161lQdRtQDmueo+t0qjPrShwr62xeO+ttVlFWY8lXG3e4L+t/60hxYBtDZXAbQBooG3HsRBtk4JQbTqtjexwbcZtiG2avkQ1QyAfLR8tGy5FTXt1Lw33zYINDUF0pQoAta2U+bQ06G1alZylWG2xeDht7a2drT2t9uB9rQhxRG3DrVqCo60oceOtzcVTraU8M

61JxXOtw/F0bQxtq61MbSxt1QBsbXQhHG2hxapt8KUmpfxtGKWCbRetV62fsTetWW0FxXet69nSbexNsm34MPJtim0ScXMAKm1CbeptAG2rkh+VWBKAOtOyC7EGbbKCRm0wbSZtM6XwbajslUEgORQA9eo0xKrgowWWjec4LSKUhsvUgHpO2uQCPOQkcLtKgQieSCnIzVGYqBZwQgnqoUVkCGXBaliNjSXoLdAN2ZGkzQ7q5M1zzTh1DzlCtfBIT

cIzolApWPUSxc/EtmLhzb4tARX+LXG4Af5xbPTpZw3QrlJ2CgB+QOkNLimbCP9tgO2lDbfZoLneqfttiBHC5SqNJU15zXJVoO2+QEDtpc3CwVgBqs2acHAAzIA7zq8AGaHfzfVUeTbBfqx4kUVd6iZFHhHH6rjRF4lFvOaSWXQuzlkB4PWgqLjVzRWIdIgtbLUT6j8t481/LdYtJM1YLTPNK7VQGQMV0/5rDWfQqQiGhh9sE8FF/qnYIzj/AumN7

M1nqEDQ47GzJSORtmW8zUBwFKX9bQktO5LAZtQAvK14Gq1VMPBBvM6CuBWsFbfFrWo5ANrtJIAMXNGAcrE5VewKdUHlVbUOL+qq7aSA6u1crVrtaBU67YStYBi27ZCA2u0CFdDYwQAW8uEE1ACW7X9A1u1mZQ2apyD27ZVGbCriVSLxfC15DfDtjm0sTYjKKu0Kza7tuq3u7Ubtuu0+7Ybtwe3+7WbtQe3bFaHtT0Dh7Z5l0Nh27aiVzuHSFRXN3

LhNXvCAG4B9rCdpok01SvIZ6dhwOWDQ7Q1lgGi4ZDw6aqttp5zTKJoUqZKDDTAtzSopyMm0FkyxaJMNWTXBtQmtx23zDZgt083nbbPN3s14LVNtJXWu8EOWJ9JXItu1GzEVqO2YiK2uTcitLTUqFJjoSo1VrRtlTXhobTLlkixGch+5UHl7ZeylOiW4reEAZ2U9pJSFue3k5bIlOVWB7eTlhuVlxbKC6VlNLfXsAyBdbWxxtu1R7T7FWo2psjqNU

o28BoKNAFXlQYNsM8VVzpft1+2yglIsd+0P7Y2tvNYv7fIAkG1sIR/t+u2QgF/tinILsT/tOQB/7ZTlAB2xeEAdGS0gHQdAYB1EHRXtkB1SgtAdWoCwHXqNg5Vc5bDlZUEjlb5lKcivwLPQROR1wdC5IaXKrUsFqvXYeU/SaB3ubfWtN+1YHUR5/CVP7eQdnK2v7QQd3UDMHQ2aJB0Xxd/trVW/7Qbl1B2vSIAdqy3NLQgATB24HfrtrB2cUOwd1

ACcHdKN+o2IHXwdIDl4QDXS5oC4AHMATECrNe21fKJDedJ8QhRseL6JiEYNDKIUDHD+cEE0nkhSmX0GOFRwgg8EaHSXKkNVh0Q05t8t3GWWLRPNdzU2LZyVdi2FdR4NueFOLY2y5Zj0AYxVuoga9CZ4wWi5GLBNCCnnTR9tLODJGO/66XEhLYgVAU3xzcXNYxjUBMZtmu3hAGjAOu1Ssbnt3R0F7YHt3R0l7WqAvTzg8BAd7AAOQOcVzqBNHYXNq

c1tHSJxGu14Hd0dfLF9HfNAxu2KSlZlhe1DHQwcpe2jHSfw4x1sAJMd/VUCHViIu9QWDMHNSGUAleuhMs1dfvnNLBUbHe0tLR0wmO0dix1qHcwAyx29HcQdee0wFQMd5u1rHcMdZe2UGlYdEx2J4JIVhopWnujtki0SAPXszUDxAPoAgEApTRDNM/Rt0gEdRzmk7esUBMx7NcIip9g7ROmymDm9qjg5fc3R5bhV0+1BtbO1R23TeYZNf24ezUsNY

EVrtZz5MfXfusTgUmUDJYYFFuiK/OM2su368ckYxeanBkfNneWCVQKdb1HjOM/VTeXiHfwtKq0/TRQFVQBCnW+1ys2QnRQU1QTiwRQAr4ALgLcpAHUQTM6NvnCsyJvQB64s1UVky21GuJs5hji70KOwxjAUPISdDwW0eu1l+yqHbT1llJ0YLadtvO3L7fztVdky1Sp5i83AwieoAglJjWtkZ6XoMeo4r3H55azNkc0NdRp58CCZ9bdNdgWNQege6

B2xeGx2VgY4pGaCK8VebZjlbx1v7YQdLoWf7fvFnkBAHrIlpu2/7XaBba0m1SYdwB2QsBYdmOXAnWwAyACuKjmd7I2edkysDuWkpdElaUCeQNfhcOWCVTGdcZ0JnXwGSZ0pnSodCuXpnRodb2XaHaQALcU2xXmdZB165QHtlB1Fnad1pZ30HeWdYG18hQcdNZ29QaxQdZ18BjptgEAsqI2do6U8HZQlrZ3tnc7lks6KFFzRWoiTBB/6OVFT1UMtU

SmyzYd1EABdnXIdC8WJncmdyh3plVmdQ52GbZmdlZ0V7SQdOZ2TnSOdhZ1r4cWdxh20HaYdDB3mHcudWZ1VnWud8dwbnVIlB8X1neN2e50ZhWOlLZ1tnQvhgFXiLQqdkby9gPUATECnQEGxA2mqDZbEUgT/zCXYm0RMeusChp2yZYQ8gipSCcMicVSj7X3Nc9DUFQup07VwmfGtkA3z7UmtJ1lArWoFkfUy1elpma3vLgc+iqAfsH42h8I0MOz4f

hVvbXMVNR3IvtJAc8iHzSsVrXXsJGkVODWaXbG5bihM9tQV9E12bXwNwy33nQ/NEADaXWUN77USLRQU1QDYtlAAmDSR2K/11aBb0PuU5Rq5zgiqiEYSFKEdRdrVwa4Ol8ScYkfA/062zepNbaLP1aztF6X9mA5VbwVc7RkdPO1L7c76Xs24LX8M2vngrZNo2CRbur6dy8gStQhBydqWlFydJilnyFuIdjihQeplisBljRntTu07klMdqe1O7WVdH

R14HR8V1/DTOe9V5YAKztKeVx3tqTcd84GmXSVdtV2vHZVdYJ2MNYaNUJ3oAPUA5RQbtEnM6p0t7ThYrfB+HRRdmypBHVdCWdjeKCkIENL2wBq49MVssCTkQV1wwfrAT9WJHR2Udp2K+bxdv24LDTSdBI1aNSU1JEk3bdOgSbmNyi2ZixozwRQWNZjDFJQ8eV3bVP7kBw6meUrtdgW1hU2EGh1hnHl4VSTEphKksoIq0bqQjoUskHgdGZ2aHWhdP

B3DldPF7nIbZX9d3502QADdQN3+8in4oN2b3hDdUN3DnU2dvB1TxfVO/qVZZLZVPbCtXTedOc0q9aqt0p3ObaZk/13mQIDdwN2Y3bF4YN043V+dvW2ZnbJxtCUJJdllNe2vzVUAHIBBZIhORjlTAt/NzHjtELnMIWLKGdKhkgS0XattyFVA9ZcmYHq63B/YD9VQjLZV9i5fjZ/V8Z6ROT/VcV3uVfYtHg3/+X7NQPLunsXJkE2MObahvAClZBM2c

l1nTaZpZYjvXb1wBzlqTTENIGVIacjdsoLrIUKEQO2O+Sz4zV1ZzblRlN3L9VIdC5WkkJ7dsXgU1ZIA+ABlTJQAY0bfzVNoJzjKFDKgfkinxqCNR1K55VG0KEpDeR7J9O181U0V4lVbnikdf4VLTa7NK02hjWtNKa3ArUJdq0XEZSV1INBVqDsMl7m84QE2RvDOIpUdkpVH7WWtLTVQ3scexV1p7ewtZEVe7QatM8BVXWXKTu2yGhkI+q18raPdx

x2PVF2wcRUTcAsFEh1hpSv1Tm3j3e0tg93T3U9wgrFV7YNdMg383XvEPgCVBpg0N9kJ3TUlV6IwTW2ZLNUG6FZwswTYnSihZ5wiCbv0yuaWneqh9NkBjRwBjlVl3f8tFd2ArZ7NF22r7X8MFo0x9SnYVALn5VldATQlYmt0BIF4DWzN3J3YSHRwYqpqXS+5s8WRQaeVuXlJ4OCy/CCAapOQ1iBNhBDdgrGoAC2tvoWEbYOt3B2O5dhdODWJlW+5m

D3YPbg9aAlWIAQ9esVEPSQ9QW1kPdyFTh3xlUQ1jVlB3bfNVN1SnVM1kaXoPeWVsoJ0PbUyOD05JHg9tSDMPavFrD3YbaQ9IW3kPVw9g2yo7ZyhuF0SakYA8uj/CLAAoRAKLY4OFFidsN2wZxbSypeBlAjA0pjo9MT1GqGJ0c1WRlSJOFXNFYKBWt2/Ld5FSJmZHf+NLp3wDQLta7XzUfkdmio1ZM5Nd6lX/PBFX55+cDWY+0pvXUcN7HjGMMEtK

D2oNfggb7nrHBjVglWJPRV4yT2iVfXliR1bqCNVDE3B3Q5ta90p7WB5k4JJPdjVDbXtoMj6inTEAIeN7bV0tna+Rea9IkoBZOY+cO3K4zYTcLA9RbyTBBkBFzb6Lf71AvCc3PttEVnOPZztrj1odbFdZ13ZHe4Nj6VaVSV1T/6UAhIpbJ2lEGYpucwhDfBNjt1RPeI1vbShQaeVeGjbPTEVZAgIZQu5hl0UNfk9od1Iirs9OF3lzYfd6ACe4IqUN

onC9Eid8jWIeRj1FFgdRb/mNFk7fh0QVRVMeMiIhvq52b3NqL651V/dUV0jPb+NAK3r/HXwAD0r7YldKwAQRSld06D5aFTYWKgJ9QjERkzJ7sGdB0WhnYT17HjXafehF+2ygm3Fr0i65hVt19mvSDGQ9fH4vX4lhL1+5sS9qPqkvdIgDtlPDdcdxl23HXJVSgAUveblVL0brZJtK4B0vVIgBo0H3RjtzSjAQJIAhYC1ptBADz1rRD7kXlzicikY1

4XHjQje4HQZMf6pKFXgwYXE3T1Ijb091OFmLUC9XkUqNT5F7j1nbfFdgD3QvQPlJXVfSi8hazEt3YNIdF5qapE9e82toB7KHdWygnikUoIXPFUszoRjAOS9sXguvZxQbr2VLB69XKhL9Sc91N1CPQAyzr33oK69chH+vRwgnr0gOeaAtEAeIBwAFWBjVEidbkjO+LbwTwSuEUOmLPga9CVp2mw5PQi+v9hMWC1dm9BlkQG156WWFSMpwz16vW49Y

z2V3QJdoEUrRXL2/sD/tqFoTijniWK5O0UqFCTZdr0RDex48gzn7XE9WRZ+AhAleKSt4VG9zoTjsDwA9fEjvVKCY70L4RO9HCBTvQy997USnZIdIb1q9TJys72cUPO9fr2TvbAW/L3fDbXtwRDY5jWgh7wFoqm9bcLy+LK4lRhwQdeFw74KvZOJJjYWzdAWDhZwFnGBXP6xrZmx3F3YjQ6dJ22uUc6dRr1QvbJ6OSr8lWEo29DIxCDSBV6mYfmUN

bbwRRHNx+0gtf29+jEd1ZESkcXEeRc8HvF8IB+gdnb18Wh9gCUYfWBgWH2foLh9Qb1MTSZd690AMvh9KeCRvcR9OH3xhIe9L83WyOAAk8BIQHAAcAA7dmeAmEDQAMqg2QBUIjlgiwAMABRAh+nTRaiAeWzifRQ2GxgiALagud5ZAFyAIamr4lJ9GjArOHvoG4Cl3T6USn0yfXvop0BK+Zp9Kn1yfR6Sen3fOHvo8n2L7YJ9eS1afXOAIZR/EEZ9m

7B76AuA8Yq2fbJ9+gCnQOIdTn3afcTd2qDufVkACSCd/t59+gA4dpJGBRnmfdJ9+n0ngSPJXDg0yv598ChL9mhU68CDAP59VVEzwLOAiIBngI8QkYD9OeyAw8i6wNMAZeY6FIvwiyieohl9UIDsgBYoOX3Y2NY4q2h1qiJ+3OAQALapBgDAtAwABAD1It0Q9AJ1iP59KX2JESiY9ICrWK4UJACiFn19VT19ADLE9uaDfUNU+DC9gLiSwQDlOIN9L

9BFYBuAM1xoVMoAeIChQHZZJthioOt9b3DIuFwMrMDKAO6AZ+mtTMt9uACrfTx01t1ggGd9W30bALfo7X0WfSXApn2wgA59vQik8JNkrMDegKcgYChFYDkA5UY4QI4cc+jj7gfygrEH8r2EUIi6PlfoY0BMAIWAM8AH8mD9sICkAJN9333wCO19dgD/CNwUiPHnIHAA430IAPD9bRIzfUNcjADaWYiAjX1AWP4S3BRVoLsgUuDMwHBOE9BRnYBIB

gBQ8cEAoNyUJPk8EIDqVV9A+P1sAIT9nWzkoGh4DYDlRgiAhTQGQK+AOQDq2Nz0ksASeOEAq7C8QNeAQAA==
```
%%