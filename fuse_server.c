#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

static int jnm_getattr( const char *path, struct stat *st )
{
    printf( "[getattr] Called\n" );
    printf( "\tAttributes of %s requested\n", path );
    
    st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
    st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
    st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
    st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now
    
    if ( strcmp( path, "/" ) == 0 ) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
    }
    else {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 1024;
    }
    
    return 0;
}

static int jnm_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi ) {
    printf( "--> Getting The List of Files of %s\n", path );
    
    filler( buffer, ".", NULL, 0 ); // Current Directory
    filler( buffer, "..", NULL, 0 ); // Parent Directory
    
    if ( strcmp( path, "/" ) == 0 ) {
        filler( buffer, "file54", NULL, 0 );
        filler( buffer, "file349", NULL, 0 );
    }
    
    return 0;
}

static int jnm_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi ) {
    printf( "--> Trying to read %s, %lu, %lu\n", path, offset, size );
    
    char file54Text[] = "Hello World From File54!";
    char file349Text[] = "Hello World From File349!";
    char *selectedText = NULL;
    
    // ... //
    
    if ( strcmp( path, "/file54" ) == 0 ) {
        selectedText = file54Text;
    } else if ( strcmp( path, "/file349" ) == 0 ) {
        selectedText = file349Text;
    } else {
        return -1;
    }  
    
    memcpy( buffer, selectedText + offset, size );
        
    return strlen( selectedText ) - offset;
}

static struct fuse_operations operations = {
    .getattr    = jnm_getattr,
    .readdir    = jnm_readdir,
    .read       = jnm_read,
};

int main( int argc, char *argv[] ) {
    return fuse_main( argc, argv, &operations, NULL );
}
