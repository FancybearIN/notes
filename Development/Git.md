# Git Notes
Initializing a New Repository in Git
To initialize a new repository in Git, use the following command:

    $ git init

This will create a new .git directory in your current working directory, which will contain all of the Git metadata for your repository..

## Default Branches:

By default, Git will create the following branches:

        - Main
        - Trunk
        - Master
        - (custom branch name)

You can specify a different default branch name when initializing the repository using the --initial-branch option.

## Git Object Types
Git uses several different types of objects to store data. The most common object types are:

- Blobs: Blobs are the basic unit of data in Git. They are used to store the contents of files.

- Trees: Trees are used to represent the directory structure of a repository. They contain references to blobs and other trees.

- Commits: Commits are used to record changes to the repository. They contain a reference to a tree, a message describing the changes, and the author and committer information.

- Tags: Tags are used to mark specific points in the history of a repository. They contain a reference to a commit and a name.


## Manage Blob and Tree in Git

**Create new object**

    git hash-object

**Read file of object**
    
    git cat-file 

**Creating new type of object** 
    
    git mktree

**Adding text in object**

    echo "hello world " | git hash-object -w -t "text/plain"

**you can encode here :-**

    echo "hello world " | base64 | git hash-object -w -t "text/plain"

**Adding modifed file**

        Git commit -a  . 

you use wildcard * . custom file/folder

**Git history**


    git log 

**Git history one linear** (Recommend user this one)

        git log --oneline --graph --decorate --all

**Git diff**

    git diff

**Git alias** 
        
        git     
        git config --global alias.hist "log --oneline --graph --decorate --all"


**Git mv**
Git move the file 
 
     git mv file.txt newfile.txt
        

**Git List**

for history of file system
        
        git list
        git ls-files
        git ls-files --others
        git ls-files --others --exclude-standard
        git ls-files --others --exclude-standard --exclude-from-history





**Git Merge**  (updates is branch name here)
 

        git merge updates
        git push origin updates 



**Git branch**

Create a branch & delete a branch 

        git branch updates
        git checkout updates
        git branch -a 
        git branch -d updates # DELETE THE BRANCH  


**Git tag**

Create the tag 

        git tag v1.0.0
        git push origin v1.0.0
        git push origin --tags
        git push origin --delete-branch
        git push origin --delete-tag
        git tag --list

Reseting stash area

        git stash pop
        git reset id      #reset to default
        git reset --hard id     
        git reset --soft id 

Tells about all logs
 
         git reflag      

**Git global**
        
        git config --global 
        git config --global --list
        git config --global --list --all

**Git Remote** 
        
        git remote add origin https://github.com/username/repo.git
        git remote -v
        git remote set-url origin https://github.com/username/repo.git 
        git remote rm origin
        
**Git Config global**


    git config --global user.email "you@example.com"
    git config --global user.name "Your Name"        

# Step to create a git repo / gitlab repo 

 step 1 :  create a repo on the site.

 step 2 :  copy link of the https .

 step 3 :  use command **git clone https://github.com/username/repo.git**

 step 4 : add you content 

 step 5 :  use command `git add .`

 step 6 :  use command `git commit -m "message"`

 step 7 :  use command `git push -u origin master`

after using this some time

 step 8 : use command `git pull`

 step 9 : use command `git fetch`

These step use when need update the local / system repo.



 














Additional Notes
- You can use the `git status` command to view the current state of your repository.

- You can use the `git add` command to add files to your staging area.
- You can use the `git commit` command to commit changes to your repository.
- You can use the `git push` command to push changes to a remote repository.
- You can use the `git pull` command to pull changes from a remote repository.
