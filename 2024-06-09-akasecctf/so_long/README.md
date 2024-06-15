# so_long \[423 Points] (23 Solves)
```
How long will it take you to escape the maze? Find the shortest path to the exit of the maze.
```
The ip `20.80.240.190:4442` is given.
---

**TL;DR:** \
We are given a maze and need to solve it. That's it. Just a coding exercise.
I used astar2d, which is a fast library written in c. The image is parsed into an array,
calculating the size per path block (Yes, it was changing each time. It took me some confusions to realize this lol)
and then we solve the maze. After it's solved we convert the solution to the `right`, `down`, etc. etc commands.

Connecting to the given ip and port via netcat gives us this
```
Welcome to so_long!

Your goal is to find the shortest path from the start point (green square) to the end point (red square).
You can move up, down, left, right, up-left, up-right, down-left, and down-right.
Insert your moves separated by spaces. For example: "up down-right right down".

Good luck!

Round 1/1000:
iVBORw0KGgoA...-snip-
```

Also I will warn you, the solve code was written like half a hour before the end of the ctf,
so you might guess it's not very pretty

[solve.py](./solve.py)
