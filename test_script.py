#''''''''''''''''' CODE DESCRIPTION '''''''''''''''''

##different_file_size_writes() writes a string of n = 2, 4, 8, 16, 32, ... , 524288 bytes to a file
 #it times each write then plots the bytes number of the file to the time to write
 
##different_file_size_reads() reads a string of n = 2, 4, 8, 16, 32, ... , 524288 bytes from a file (written
 #during prev test). It times each read then plots the bytes number of the file to the time to read
 
##consec_file_accesses_test("524288.txt") reads a string of n = 524288 bytes from a file (written during
 #first test). It timese each read then plots the access order against the time to read

##outputs from test are plotted and saved in "/plots/" in the specified PLOTS_OUTPUT_FOLDER

#''''''''''''''''' IMPORTS '''''''''''''''''

import random, string

from os import listdir, path, makedirs
from datetime import datetime

import matplotlib.pyplot as plt 

#''''''''''''''''' CONSTANTS '''''''''''''''''


NUM_CONSEC_OPS = 100
CONSEC_TEST__FILE_SIZE = 2000
FILE_SIZE_RANGE = [2**j for j in range(1,20)]

#------- READ HERE ---------
##CHANGE DIR_NAME TO TEST ON FUSE FILE SERVER...
DIR_NAME = "/users/lidukhov/P1/root/filesystem/" ##for FUSE test...
#DIR_NAME = "/Users/miaweaver/Documents/Graduate/Coursework/Spring_2023/CS739/P1/Fuse-739-jnm/" ##for Mia's local test...

PLOTS_OUTPUT_FOLDER = "/users/lidukhov/P1/" ##for FUSE test...
#PLOTS_OUTPUT_FOLDER = "/Users/miaweaver/Documents/Graduate/Coursework/Spring_2023/CS739/P1/Fuse-739-jnm/" ##for Mia's local test...



#''''''''''''''''' FILE OPS '''''''''''''''''

def read_file(inputs):
    file_name = inputs[0]
    folder = DIR_NAME + "test_files/"
    
    if not path.exists(folder):
       makedirs(folder)
       
    file = open(folder + file_name, "r")
    file_string = file.read()
    return file_string

def write_file(inputs):
    text, file_name = inputs
    folder = DIR_NAME + "test_files/"
    
    if not path.exists(folder):
       makedirs(folder)

    file = open(folder + file_name, "w") 
    file.write(text)
    file.close() 
    return

#'''''''''''''''' END FILE OPS '''''''''''''


#'''''''''''''' FILE OP HELPERS ''''''''''''

def generate_text(n): ##generate text to write to file
    ##https://stackoverflow.com/questions/2511222/efficiently-generate-a-16-character-alphanumeric-string for next line of code
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + "\n") for _ in range(n))


def time_func(func, args): ##run and time file op
    start = datetime.now()
    func(args) ##run input func with args
    end = datetime.now()
    return ( (end - start ).total_seconds() * 1000000 )

#'''''''''''' END FILE OP HELPERS ''''''''''''


#''''''''''' PLOT FILE OP LATENCIES ''''''''''

def plot_latencies(times_by_file, title, xlabel):
    fig, ax = plt.subplots(figsize=(20, 10))
    files, times = list( times_by_file.keys() ), list( times_by_file.values() )
    plt.plot(files, times, "--",
             color="red", linestyle="solid", marker = "o")
    
    if "Repeated" not in title:
        ax.set_xscale('log')
    plt.rcParams.update({'font.size': 22})
    plt.ylabel( "Latency (ms)" )
    plt.xlabel( xlabel )
    plt.title(title)
    
    folder = PLOTS_OUTPUT_FOLDER + "plots/"
    
    if not path.exists(folder):
        makedirs(folder)
    print(folder + title)
    plt.savefig(folder + title + ".png", bbox_inches='tight')
    plt.show()

    return

#'''''''' END PLOT FILE OP LATENCIES ''''''''


#''''''''''''' FILE OP TESTS ''''''''''''''''

def consec_file_accesses_test(file_name): ##looking for reduced latency in consecutive file reads
    times = {}
    for i in range(NUM_CONSEC_OPS):
        times[i] = time_func( read_file, [file_name] )
    plot_latencies( times, "Repeated File Reads", "Access Count" ) 
    return times

def repeated_writes_test(file_name): ##looking for no spikes in latency... testing consecutive writes of files of equal size
    text = generate_text(CONSEC_TEST__FILE_SIZE)
    times = {}
    for i in range(NUM_CONSEC_OPS):
        times[i] = time_func( write_file, [text] )
    plot_latencies( times, "Repeated File Writes", "Access Count" ) 
    return times

def different_file_size_writes():
    times = {}
    for i in FILE_SIZE_RANGE:
        text = generate_text(i)
        bytes_len = len(text.encode('utf-8'))  ##get file size in bytes
        times[bytes_len] = time_func( write_file, [text, str(bytes_len) + ".txt"] )
    plot_latencies( times, "Different File Size Writes", "File Sizes (bytes)") 
    return times
        
def different_file_size_reads():
    test_files = [f for f in listdir(DIR_NAME + "test_files/")] ##https://stackoverflow.com/questions/3207219/how-do-i-list-all-files-of-a-directory
    times = {}
    for file_name in test_files:
        if ".txt" not in file_name:
            continue
        bytes_len = file_name.split(".")[-2]
        times[bytes_len] = time_func(read_file, [file_name])

    plot_latencies( times, "Different File Size Reads", "File Size (bytes)" ) 
    return times   

#''''''''''' END FILE OP TESTS '''''''''''


different_file_size_writes()
different_file_size_reads()
consec_file_accesses_test("524288.txt")
