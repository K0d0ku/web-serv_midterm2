# web-service development 2nd midterm task
___Update: Dont worry i excluded the `.gitignore` on purpose cause i wanted to show the [.env](https://github.com/K0d0ku/web-serv_midterm2/blob/main/.env), [swagger docs](https://github.com/K0d0ku/web-serv_midterm2/tree/main/docs) and [logs](https://github.com/K0d0ku/web-serv_midterm2/tree/main/logs) on purpose___  

## in here i show my process/progress in the making of this project and fulfilling its requirements  
!!! The list of **_Tools_** and **_Packages_** are listed in [README.md](https://github.com/K0d0ku/web-serv_midterm2/blob/main/README.md), and previous process can be seen in [the_process.md](https://github.com/K0d0ku/web-serv_midterm1/blob/master/%23images_and_files/the_process.md)  
  
#### Table of contents:  
- [Requirements](#requirements)
- [Process](#process)
- [1. Implementing CRUD operations using an external REST style](#1-implementing-crud-operations-using-an-external-rest-style)
  - [1.1 Implementing validation](#11-implementing-validation)
- [2. Implementing dependency injection](#2-implementing-dependency-injection)
  - [2.1 Logging](#21-logging)
  - [2.2 Repository pattern using a Postgres database](#22-repository-pattern-using-a-postgres-database)
- [3. API testing](#3-api-testing)
  - [3.1 Using net/http](#31-using-nethttp-or-its-equivalent)
  - [3.2 Using Postman or other equivalents](#32-using-postman-or-other-equivalents)
- [4. Implementing API authorization (JWT or other options)](#4-implementing-api-authorization-jwt-or-other-options)
- [Additional content](#additional-content)

## Requirements
i was given another list of requirements to make the project by following it so i can pass my 2nd midterm  
the list of requirements are:
![requirements2](https://github.com/K0d0ku/web-serv_midterm2/blob/main/%23images_and_files_2/requirements2.png)  
and following that list i have fulfilled the needed job to do:

## Process

I kinda had a bit of experience with .Net Maui and made an android app with a Local Database that also includes some of the requirements like: CRUD, DataAnnotation etc. from the projects like: android app development with its local database [Link🔗](https://github.com/K0d0ku/cloud_app_dev_exam_project) and making simple api in .Net Core Web API with database integration and user's permission to certain types of data [Link🔗](https://github.com/K0d0ku/web-serv_midterm1/blob/master/%23images_and_files/the_process.md)  

### Idea
I took the inspiration and idea from my [.Net B2B2C app](https://github.com/K0d0ku/cloud_app_dev_exam_project), [Postgres Mustream database](https://github.com/K0d0ku/mustream) and [.Net Core Web Api project](https://github.com/K0d0ku/web-serv_midterm1), and used some of their functions in this project.  
The idea is simple, make an api with several roles with `RBAC` for certain data and api endpoints, and mainaining it all with simple data validation and dto to keep the implementation clean.
for the idea / purpose i reused the idea from my Postgres Mustream Database and B2B2C Maui app projects, which also has RBAC, and thought of something like the following:
there will be 2 roles:
- Artist
- Listener

and `Admin` but its not technically a role,  
and 3 Api endpoint categories:  
- User  
- Music  
- Genre

and with RBAC each role will have their own access to the endpoints across these categories:  
#### User Endpoints RBAC:
| Endpoint            | Artist | Listener | Admin |
| ------------------- | ------ | -------- | ----- |
| POST `/register`    | Allowed      | Allowed        | Allowed     |
| POST `/login`       | Allowed      | Allowed        | Allowed     |
| GET `/users`        | Denied      | Denied        | Allowed     |
| GET `/users/:id`    | ID Locked     | ID Locked       | Allowed     |
| PUT `/users/:id`    | ID Locked     | ID Locked       | Allowed     |
| DELETE `/users/:id` | ID Locked     | ID Locked       | Allowed     |  

#### Music Endpoints RBAC:  
| Endpoint            | Artist | Listener | Admin |
| ------------------- | ------ | -------- | ----- |
| GET `/music`        | Allowed      | Allowed        | Allowed     |
| GET `/music/:id`    | Allowed      | Allowed        | Allowed     |
| POST `/music`       | Allowed      | Denied        | Allowed     |
| PUT `/music/:id`    | ID Locked     | Denied        | ID Locked    |
| DELETE `/music/:id` | ID Locked     | Denied        | ID Locked    |  

#### Genre Endpoints RBAC:
| Endpoint             | Artist | Listener | Admin |
| -------------------- | ------ | -------- | ----- |
| GET `/genres`        | Allowed      | Allowed        | Allowed     |
| GET `/genres/:id`    | Allowed      | Allowed        | Allowed     |
| POST `/genres`       | Denied      | Denied        | Allowed     |
| PUT `/genres/:id`    | Denied      | Denied        | Allowed     |
| DELETE `/genres/:id` | Denied      | Denied        | Allowed     |

in simple terms, upon registration, login and JWT Bearer authorization:
- Admin can do everything and additionally:
  - Create genres (admin only),
  - Update genres (admin only),
  - Delete genres (admin only),
- Artist can:
  - Create music,
  - Update music (only own),
  - Delete music (Only own),
  - Get all music or get by id,
  - Can get all genres or get by id,
  - Get user data (only own),
  - Can update credentials (only own),
  - Can delete account (only own)
- Listener can:
  - Get all music or get by id,
  - Can get all genres or get by id,
  - Get user data (only own),
  - Can update credentials (only own),
  - Can delete account (only own)



## 1. Implementing CRUD operations using an external REST style
Content here.

### 1.1 Implementing validation
Content here.

## 2. Implementing dependency injection
Content here.

### 2.1 Logging
Content here.

### 2.2 Repository pattern using a Postgres database
Content here.

## 3. API testing
Content here.

### 3.1 Using net/http (or its equivalent)
Content here.

### 3.2 Using Postman or other equivalents
Content here.

## 4. Implementing API authorization (JWT or other options)
Content here.



### Additional content  
Most of the image and files content is located in: [↳Images and Files_2](https://github.com/K0d0ku/web-serv_midterm2/tree/main/%23images_and_files_2) folder  

#### Roadmap i made in .word
[2nd-midterm.docx](#)
