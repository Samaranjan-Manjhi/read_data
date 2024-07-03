#define pr_fmt(fmt) "nocrypt: " fmt
#include <linux/fs.h>
#include <linux/mm.h>
#include <asm/mman.h>
#include <asm/stat.h>
#include <asm/types.h>
#include <asm/fcntl.h>
#include <linux/slab.h>
#include <asm/signal.h>
#include <linux/mman.h>
#include <linux/init.h>
#include <asm/unistd.h>
#include <linux/sysfs.h>
#include <linux/rwsem.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/unistd.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/fdtable.h>
#include <linux/version.h>
//#include <linux/openat2.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/fsnotify.h>
#include <linux/sched/signal.h>
#include <linux/fsnotify_backend.h>


MODULE_DESCRIPTION("Detect and kill ransomware");
MODULE_AUTHOR("Mahakal");
MODULE_LICENSE("GPL");

static unsigned int max_rename = 12;
module_param(max_rename, int, 0);
static bool behaviour_detection = false;
module_param(behaviour_detection, bool, 0);
static unsigned int rename_count = 0;
static unsigned int target_pid = 0;
#define BLACKLIST_SIZE 23
//static char *blacklist_ext[] = {"Clop","iFire","conti","monti","PUUUK", "Cheers","lockbit", "mitu", " miza", " miqe", "gaqq", "waqq", "gayn", "gazp", "aghz", "bhui", "bhtw", "anxz", "ahgr", "ahui", "ahtw", "neon", "neqp"};
static struct list_head *prev_module;

static const char *filename = "/home/workspace_2.55_backup/workspace/newpatterns.txt";
#define BUFFER_SIZE 2048
static char *pattern[BUFFER_SIZE] = "";

void hideme(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
}

void showme(void)
{
	list_add(&THIS_MODULE->list, prev_module);
}

static bool module_unlocked = false;
#define MAX_PWD_LEN 100
static char *password = "n0Cr1pt";
module_param(password, charp, 0000);
static char *nocrypt_buf;
static DECLARE_RWSEM(nocrypt_rwlock);
static char *pwd_buf;
static DECLARE_RWSEM(pwd_rwlock);
static struct kobject *nocrypt_kobj;

static ssize_t nocrypt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return 0;
}

static ssize_t nocrypt_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	int len;
	down_write(&pwd_rwlock);
	memset(pwd_buf, 0, MAX_PWD_LEN);
	len = (count > MAX_PWD_LEN)? MAX_PWD_LEN: count;
	strncpy(pwd_buf, buf, len);
	up_write(&pwd_rwlock);
	if (strncmp(password, pwd_buf, len) == 0) {
		module_unlocked = true;
		showme();
		pr_info("Module unlocked");
	}
	return len;
}

static struct kobj_attribute nocrypt_attribute = __ATTR(nocrypt, 0600, nocrypt_show, nocrypt_store);
static struct attribute *attrs[] = {
	&nocrypt_attribute.attr,
	NULL,
};
static struct attribute_group attr_group = {
	.attrs = attrs,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;
	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#define USE_FENTRY_OFFSET 0
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;
	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;
	err = fh_resolve_hook_address(hook);
	if (err)
		return err;
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION
		| FTRACE_OPS_FL_IPMODIFY;
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}
	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}
	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;
	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}
	return 0;
error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}
	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;
	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif
-----------------------------------
#define BUFFER_SIZE 4096
int line_number=1;
    loff_t offset = 0;

// Open a file
struct file *file_open(const char *path, int flags, int rights) {
    struct file *filp = NULL;
    filp = filp_open(path, flags, rights);
    if (IS_ERR(filp)) {
        return NULL;
    }
    return filp;
}

// Close a file
void file_close(struct file *file) {
    filp_close(file, NULL);
}

// Read data from a file
ssize_t file_read(struct file *file, unsigned char *data, loff_t offset, size_t size) {
    mm_segment_t oldfs;
    ssize_t ret;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    ret = kernel_read(file, data, size, &offset);
               // printk(KERN_INFO "bytes read %zd \n", ret);

    set_fs(oldfs);
    return ret;
}

// Function to remove leading and trailing whitespace
char *trim(char *str) {
    char *end;

    // Trim leading whitespace
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0)  // All spaces?
        return str;

    // Trim trailing whitespace
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}


// Function to filter and print lines containing the pattern
void grep_pattern(const char *pattern, const unsigned char *buffer, ssize_t size) {

    char *line;
    unsigned char *pos = (unsigned char *)buffer;
    char *line_lower;
    char *prev_line;
     // Initialize line number
    int prev_line_number = -1; // Initialize previous line number

    // Convert pattern to lowercase
    char *pattern_lower = kstrdup(pattern, GFP_KERNEL);
    for (int i = 0; pattern_lower[i]; i++) {
        pattern_lower[i] = tolower(pattern_lower[i]);
    }
//    line_number=line_number-1;

    // Iterate over each line in the buffer
    while ((line = strsep((char **)&pos, "\n")) != NULL) {
        // Skip empty lines
        if (line[0] == '\0'){
            line_number++;
            continue;
          }
        line_lower = kstrdup(line, GFP_KERNEL); // Convert line to lowercase
        for (int i = 0; line_lower[i]; i++) {
            line_lower[i] = tolower(line_lower[i]);
        }

        // Check if the line contains the pattern (extension)
        if (strstr(line_lower, pattern_lower) != NULL) {
            // Print the matched extension and line number
            printk(KERN_INFO "%s found in line %d: %s\n", pattern, line_number, line);
            // Print the previous line if available
            if (prev_line_number != -1) {
                printk(KERN_INFO "Nearest line without .extension found in line %d: %s\n", prev_line_number, prev_line);
            }
        }

        // Update previous line number if the current line does not contain a .extension and is not empty
        if (strstr(line_lower, ".")==NULL && line_lower[0]!='\0') {
            prev_line_number = line_number;
            prev_line=line;
        }

        kfree(line_lower);
        line_number++; // Increment line number
    }
    line_number--;
    kfree(pattern_lower);
}

// Function to read file and grep pattern
static int read_and_grep_file(const char *filename, const char *pattern) {
    struct file *file;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
   // loff_t offset = 0;

    printk(KERN_INFO "Reading and grepping file: %s\n", filename);

    // Open the file
    file = file_open(filename, O_RDONLY, 0);
    if (!file) {
        printk(KERN_ERR "Failed to open file: %s\n", filename);
        return -ENOENT;
    }

    // Read and filter data from the file until no more data is left
    do {
        bytes_read = file_read(file, buffer, offset, sizeof(buffer));
        if (bytes_read < 0) {
            printk(KERN_ERR "Failed to read from file: %s\n", filename);
            file_close(file);
            return bytes_read;
        }
        // Filter and print lines containing the pattern
        grep_pattern(pattern, buffer, bytes_read);
//      printk(KERN_INFO "Current offset: %lld\n", (long long)offset);
        offset += bytes_read;
//      printk(KERN_INFO "Current offset: %lld\n", (long long)offset);
    } while (bytes_read == sizeof(buffer));

    // Close the file
    file_close(file);

    return 0;
}


-----------------------------------

static bool kill_task(struct task_struct *task) {
	int signum = SIGKILL;
	struct kernel_siginfo info;
	memset(&info, 0, sizeof(struct kernel_siginfo));
	info.si_signo = signum;
	int ret = send_sig_info(signum, &info, task);
	if (ret < 0)
	{
		printk(KERN_INFO "error sending signal to %d\n", target_pid);
		return -1;
	}
	else 
	{
		printk(KERN_INFO "Target pid %d has been killed\n", target_pid);
		return 0;
	}
}

static bool check_rename(char *oldname, char *newname) {
	struct task_struct *task;
	task = current;
	if (target_pid == task->tgid) {
		rename_count++;
	} else {
		target_pid = task->tgid;
		rename_count = 0;
	}
	int old_index = 0;
	int new_index = 0;
	int old_point_index = 0;
	int new_point_index = 0;
	int nmax = 200;
	//loop max nmax times for oldname
	for (old_index = 0; old_index < nmax; old_index++) {
		if (oldname[old_index] == 0)
			break;
		else if (oldname[old_index] == '.') {
			old_point_index = old_index;
		}
	}
	//loop max nmax times for newname
	for (new_index = 0; new_index < nmax; new_index++) {
		if (newname[new_index] == 0)
			break;
		else if (newname[new_index] == '.') {
			new_point_index = new_index;
		}
	}
	if ((old_point_index > 0) && (old_index < nmax)) {
		char *old_extension = oldname + old_point_index + 1;
		for (int i = 0; i < BLACKLIST_SIZE; i++) {
			if (strcmp(old_extension, blacklist_ext[i]) == 0) {
				pr_info("{\"program\":\"%s\",\"pid\":%d,\"status\":\"detected\",\"type\":\"%s\",\"reason\":\"known extension\",\"details\":\"renaming %s to %s\"}\n", task->comm, target_pid, old_extension, oldname, newname);
				kill_task(task);
				return false;
			}
		}
	}
	if ((new_point_index > 0) && (new_index < nmax)) {
		char *new_extension = newname + new_point_index + 1;
		for (int i = 0; i < BLACKLIST_SIZE; i++) {
			if (strcmp(new_extension, blacklist_ext[i]) == 0) {
				pr_info("{\"program\":\"%s\",\"pid\":%d,\"status\":\"detected\",\"type\":\"%s\",\"reason\":\"known extension\",\"details\":\"renaming %s to %s\"}\n", task->comm, target_pid, new_extension, oldname, newname);
				kill_task(task);
				return false;
			}
		}
	}
	//Behavior check
	if (behaviour_detection) {
		// if the same process pid is renaming more than n files, kill it
		if (rename_count >= max_rename) {
			pr_info("{\"program\":\"%s\",\"pid\":%d,\"status\":\"suspicious\",\"type\":\"unknown\",\"reason\":\"renaming too much files\",\"details\":\"last file renamed %s to %s\"}\n", task->comm, target_pid, oldname, newname);
			kill_task(task);
			rename_count = 0;
			return false;
		}
	}
	return true;
}

// Function to get file extension
static char *get_extension(const char *filename)
{
	const char *dot = strrchr(filename, '.');
	if (!dot || dot == filename) {
		return NULL; // No extension found
	}
	//return (char *)(dot + 1); // Return the extension (excluding the dot)
	//return strdup(dot + 1);
	return strdup(dot);
}

/*-------------------------------*/
static struct list_head file_list_head;

struct file_info {
                  struct list_head list;
                  char name[256]; // Adjust the buffer size as needed
                  bool is_directory;
};

void add_file_info(const char *filename, bool is_directory) {
                  struct file_info *info = kmalloc(sizeof(struct file_info), GFP_KERNEL);
                  if (!info) {
                                         printk(KERN_ERR "Failed to allocate memory for file info\n");
                                         return;
                  }
                  strncpy(info->name, filename, sizeof(info->name));
                  info->is_directory = is_directory;
                  list_add_tail(&info->list, &file_list_head);
}

void remove_file_info(const char *filename) {
                  struct file_info *info;
                  list_for_each_entry(info, &file_list_head, list) {
                                         if (strcmp(info->name, filename) == 0) {
                                                                list_del(&info->list);
                                                                kfree(info);
                                                                break;
                                         }
                  }
}

void print_file_info(const char *operation, const char *filename, bool is_directory) {
                  if (is_directory) {
                                         printk(KERN_INFO "%s directory visited: %s\n", operation, filename);
                  } else {
                                         printk(KERN_INFO "%s file opened: %s\n", operation, filename);
                  }
}

// Function to log file information (replace with your actual implementation)
static void log_file_info(const char *method, const char *filename, bool is_write)
{
    printk(KERN_INFO "File opened with method '%s': %s (write access: %s)\n", method, filename, is_write ? "true" : "false");
}

/*-------------------------------*/

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_open)(struct pt_regs *regs);
/*static asmlinkage long fh_sys_open(struct pt_regs *regs)
{
    long ret = 0;
    char kernel_filename[256]; // Adjust the buffer size as needed
    const char __user *filename = (const char __user *)regs->di;
    int flags = (int)regs->si;
    umode_t mode = (umode_t)regs->dx;

    if (copy_from_user(kernel_filename, filename, sizeof(kernel_filename) - 1)) {
        printk(KERN_ERR "Failed to copy filename from user space (open)\n");
        return -EFAULT;
    }

    kernel_filename[sizeof(kernel_filename) - 1] = '\0';

    ret = real_sys_open(regs);

    if (ret >= 0) {
//        add_file_info(kernel_filename, false); // Assuming add_file_info is defined elsewhere
        printk(KERN_INFO "File opened: %s\n", kernel_filename);
    }

    return ret;
}
*/
// Custom open syscall handler
static asmlinkage long fh_sys_open(struct pt_regs *regs)
{
    long ret = 0;
    char kernel_filename[256]; // Adjust the buffer size as needed
    const char __user *filename = (const char __user *)regs->di;
    int flags = (int)regs->si;
    umode_t mode = (umode_t)regs->dx;

    // Copy filename from user space to kernel space
    if (copy_from_user(kernel_filename, filename, sizeof(kernel_filename) - 1)) {
        printk(KERN_ERR "Failed to copy filename from user space (open)\n");
        return -EFAULT;
    }

    kernel_filename[sizeof(kernel_filename) - 1] = '\0';

    // Check if the file is opened for writing
    bool is_write = (flags & O_WRONLY) || (flags & O_RDWR);

    // Check for specific methods: touch, echo, vim, vim.tiny
    const char *method = NULL;
    if (strstr(current->comm, "touch"))
        method = "touch";
    else if (strstr(current->comm, "echo"))
        method = "echo";
    else if (strstr(current->comm, "vim"))
        method = "vim";
    else if (strstr(current->comm, "vim.tiny"))
        method = "vim.tiny";

    // Log file information if one of the methods matches
    if (method) {
        log_file_info(method, kernel_filename, is_write);
    }

    // Call the real sys_open function
    ret = real_sys_open(regs);

    return ret;
}

static asmlinkage long (*real_sys_rename)(struct pt_regs *regs);
static asmlinkage long fh_sys_rename(struct pt_regs *regs)
{
	long ret = 0;
	char *oldname = (char*)regs->di;
	char *newname = (char*)regs->si;
	if (check_rename(oldname, newname)) {
		ret = real_sys_rename(regs);
	}
	return ret;
}


static asmlinkage long (*real_sys_renameat2)(struct pt_regs *regs);
static asmlinkage long fh_sys_renameat2(struct pt_regs *regs)
{
	long ret = 0;
	struct task_struct *task;
	task = current;
	//const int olddirfd = (int)regs->di;
	const char __user *oldname = (const char __user *)regs->si;
	//const int newdirfd = (int)regs->dx;
	const char __user *newname = (const char __user *)regs->r10;

	char oldname_buf[256]; // Adjust the size as needed
	char newname_buf[256]; // Adjust the size as needed
	// Copy oldname and newname from user space to kernel space
	if (copy_from_user(oldname_buf, oldname, sizeof(oldname_buf)) ||
			copy_from_user(newname_buf, newname, sizeof(newname_buf))) {
		return -EFAULT; // Error copying data from user space
	}
	// Null-terminate the strings
	oldname_buf[sizeof(oldname_buf) - 1] = '\0';
	newname_buf[sizeof(newname_buf) - 1] = '\0';
	// Log the old and new names
	printk(KERN_INFO "Renameat2: \n\tFrom: %s\n\tTo: %s\n", oldname_buf, newname_buf);
	// Handle checks for both source and destination files
	char *source_extension = get_extension(oldname_buf);
	char *dest_extension = get_extension(newname_buf);
	// Handle source file checks
	if (source_extension) {
		for (int i = 0; i < BLACKLIST_SIZE; i++) {
			if (strcmp(source_extension, blacklist_ext[i]) == 0) {
				pr_info("Blacklisted extension detected in source file: %s\n", source_extension);
				pr_info("{\"program\":\"%s\",\"pid\":%d,\"status\":\"detected\",\"type\":\"%s\",\"reason\":\"known extension\",\"details\":\"renaming %s to %s\"}\n", task->comm, task->tgid, source_extension, oldname_buf, newname_buf);
				kill_task(current); // Kill the current process
				return -EPERM; // Return an error to indicate failure
			}
		}
	}

	// Handle destination file checks
	if (dest_extension) {
		for (int i = 0; i < BLACKLIST_SIZE; i++) {
			if (strcmp(dest_extension, blacklist_ext[i]) == 0) {
				pr_info("Blacklisted extension detected in destination file: %s\n", dest_extension);
				pr_info("{\"program\":\"%s\",\"pid\":%d,\"status\":\"detected\",\"type\":\"%s\",\"reason\":\"known extension\",\"details\":\"renaming %s to %s\"}\n", task->comm, task->tgid, dest_extension, oldname_buf, newname_buf);
				kill_task(current); // Kill the current process
				return -EPERM; // Return an error to indicate failure
			}
		}
	}
	// Call the real system call
	ret = real_sys_renameat2(regs);
	return ret;
}


static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);
static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
	int ret = 0;
	struct task_struct *task = current;
	//int dfd = (int)regs->di;
	const char __user *filename = (const char __user *)regs->si;
	int flags = (int)regs->dx;
	//umode_t mode = (umode_t)regs->r10;
	char filename_buf[256];
	if(copy_from_user(filename_buf, filename, sizeof(filename_buf)))
	{
		return -EFAULT;
	}
	filename_buf[sizeof(filename_buf) - 1] = '\0';
	if ((flags & O_WRONLY) && (flags & O_CREAT) && !(flags & O_APPEND))
	{
		pr_info("File created : %s\n", filename);
	}
	if (target_pid == task->tgid) {
		rename_count++;
	} else {
		target_pid = task->tgid;
		rename_count = 0;
	}
	int index = 0;
	int point_index = 0;
	int nmax = 200;
	//loop max nmax times
	for (index = 0; index < nmax; index++) {
		if (filename[index] == 0)
			break;
		else if (filename[index] == '.') {
			point_index = index;
		}
	}
	if ((point_index > 0) && (index < nmax)) {
		const char *extension = filename+point_index+1;
		for (int i = 0; i < BLACKLIST_SIZE; i++) {
			if (strcmp(extension,blacklist_ext[i]) == 0) {
				pr_info("{\"program\":\"%s\",\"pid\":%d,\"status\":\"detected\",\"type\":\"%s\",\"reason\":\"known extension\",\"details\":\"creating %s\"}\n", task->comm, target_pid, extension, filename);
				kill_task(task);
				return false;
			}
		}
	}
	// Call the original sys_openat function
	ret = real_sys_openat(regs);
	return ret;
}

#else
static asmlinkage long (*real_sys_open)(const char __user *filename, int flags, umode_t mode);
static asmlinkage long fh_sys_open(const char __user *filename, int flags, umode_t mode)
{
                  long ret = 0;
                  char kernel_filename[256]; // Adjust the buffer size as needed
                  if (copy_from_user(kernel_filename, filename, sizeof(kernel_filename) - 1)) {
                                         //printk(KERN_ERR "Failed to copy filename from user space----------(open)\n");
                                         return -EFAULT;
                  }
                  kernel_filename[sizeof(kernel_filename) - 1] = '\0';
                  ret = real_sys_open(filename, flags, mode);
                  if (ret >= 0) {
                                         add_file_info(kernel_filename, false);
                                         print_file_info("File", kernel_filename, false);
                  }
                  return ret;
}


static asmlinkage long (*real_sys_rename) (const char __user *oldname, const char __user *newname);
static asmlinkage long fh_sys_rename(const char __user *oldname, const char __user *newname)
{
	long ret = 0;
	if (check_rename(oldname, newname)) {
		ret = real_sys_rename(oldname, newname);
	}

	return ret;
}


static asmlinkage long (*real_sys_openat) (int dfd, const char __user *filename, int flags, umode_t mode);
static asmlinkage long fh_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
	if ((flags & O_WRONLY) && (flags & O_CREAT) && !(flags & O_APPEND)) {
		pr_info("File created : %s\n", filename);
	}
	// Call the original sys_openat function
	return real_sys_openat(dfd, filename, flags, mode);
}

#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
{					\
	.name = SYSCALL_NAME(_name),	\
	.function = (_function),	\
	.original = (_original),	\
}

static struct ftrace_hook hooks[] = {
	HOOK("sys_open", fh_sys_open, &real_sys_open),
	HOOK("sys_rename", fh_sys_rename, &real_sys_rename),
	HOOK("sys_renameat2", fh_sys_renameat2, &real_sys_renameat2),
	HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
};

static int nocrypt_init(void)
{
//	const char *filename = "/home/workspace_2.55_backup/workspace/newpatterns.txt"; // Modify this to your file path
//    	const char *pattern = ".zeon";
	int ret;

    	ret = read_and_grep_file(filename, pattern);
    	if (ret != 0) {
        	return ret;
    	}

    		int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err)
		return err;
	// Create "nocrypt" kobject
	nocrypt_kobj = kobject_create_and_add(".nocrypt", kernel_kobj);
	if (!nocrypt_kobj)
		return -ENOMEM;
	// Allocate space for nocrypt_buf and pwd_buf
	nocrypt_buf = (char*) kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!nocrypt_buf) {
		pr_err("Cannot allocate memory for nocrypt buffer\n");
		kobject_put(nocrypt_kobj);
		return -ENOMEM;
	}
	pwd_buf = (char*) kzalloc(MAX_PWD_LEN, GFP_KERNEL);
	if (!pwd_buf) {
		pr_err("Cannot allocate memory for password buffer\n");
		kfree(nocrypt_buf);
		kobject_put(nocrypt_kobj);
		return -ENOMEM;
	}
	err = sysfs_create_group(nocrypt_kobj, &attr_group);
	if (err) {
		pr_err("Cannot register sysfs attribute group\n");
		kfree(nocrypt_buf);
		kfree(pwd_buf);
		kobject_put(nocrypt_kobj);
	}
	hideme();
	
	int ret;
        ret = read_and_grep_file(filename, pattern);
        if (ret != 0) {
                return ret;
        }

	// Get the file extension
    	extension = get_extension(filename);
    	if (!extension) {
        	printk(KERN_ERR "No extension found in filename: %s\n", filename);
        	return -EINVAL; // Return error if no extension found
    	}

	// Copy the extension to pattern buffer
    	strncpy(pattern, extension, BUFFER_SIZE - 1);
    	pattern[BUFFER_SIZE - 1] = '\0'; // Ensure null termination

	pr_info("nocrypt loaded (max_rename=%d,behaviour_detection=%d)\n",max_rename,behaviour_detection);
	return 0;
}
module_init(nocrypt_init);

static void nocrypt_exit(void)
{
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	kfree(nocrypt_buf);
	kfree(pwd_buf);
	kobject_put(nocrypt_kobj);
	pr_info("nocrypt unloaded\n");
}
module_exit(nocrypt_exit);
