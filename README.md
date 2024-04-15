# Secure Chat Application
By: Max Nurzia and William Liu

## Details
This is a secure chat application that utilizes a combination of SRP (to mutually authenticate clients to the server) and Otway-Rees (to leverage an authenticated server to mutually authenticate clients to each other).

[More Information on the Protocol](https://docs.google.com/presentation/d/13a9pzWd8g1uTYHiGqeNUbgshdO1-oOgH0gNdSAW6ukk/edit?usp=sharing)

## Dependencies
- cryptography library

## Run Instructions
1) Clone the repository
2) Create a user (optional, see the following section for details)
3) Start up the server by running "python proj.py server <server_ip> <server_port>"
4) Start up a client by runnign "python proj.py client <server_ip> <server_port> <username> <password>"

## Add User Instructions
Run "python proj.py add_user <username> <password>"

## Available Client Information
Format: <username> - <password>
ClientA - password
ClientB - #Pangaea4Life
ClientC - ThisIsStrong4Sure!!