# idor 

**where to find idor ??**

IDors can be find at anywhere in site

Major area
        
        baskets
        delete items
        refer
        like
        comment
        admin
        account delete
        profile photos

But keep eye on the 

1. IDs or value that could be IDs
2. Api full of idors
3. Complex permission hirarchies.(adversite site or software on the site like slack, instagram ads panel likely)
4. CRUD Functionality (Create Read Update Delete)


## CRUD 

In a site basic testing 

     // account permissions
like User1 perm to USer2 perm or admin perm

## how the rest api design works 
// request working
## Create

     POST /post

## READ

        GET/posts/1 <= that's ID
## Update
        
        POST /posts/1
        PUT /posts/1
        POST /posts/1/edit
## Delete

        Delete /posts/1
        POST /posts/1/delete
##

vaild  the idors


- We can access something without being logged on


  - Create an account /log in
   - perfrom a bunch of requests.
  - Go to repeater and remove the COOKie.
      - Effectively treating the requests as if they came from no particular user.
  - Check ans see it they're caused something to happen to our account. 


- Access something on our Account when Logged onto another account
  - Create an account/log in (USER A)
  - perfrom a bunch of requests.
  - Create an account.log in (USER B)

  - Goto Repeater And change **A's Cookie to new cookie (B's).**

  - Check and see if they 've caused something to happen to account A rather than B.

- Or access some admin functionality , even if we don't have permission.
       
## Chaning the cookies
- when we logout. it may remove the session from the server. ( soln => stay login ) 

- it effectively allows us to quickly login as another user.
  - without removing the previous session
- While removing them allows us to logut easily.
- but wait what's session ??

#
#

# youtube Resouces

bug bounty Reports Explaineds : https://www.youtube.com/watch?v=wx5TwS0Dres

tell how to attack
https://www.youtube.com/watch?v=B_WESrC-wWs

IDOR usually found
bug Crowd => https://youtu.be/B_WESrC-wWs?si=P4RXEHSSYMRqmAm0
