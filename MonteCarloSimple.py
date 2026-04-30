# MonteCarlo Example
from random import randint
class Simulation:
    def __init__(self, n):
        self.n = n
        self.sim = {}
    def run(self):
        for k in range(self.n):
            # FIX: use tuple instead of set
            self.sim[k] = (
                randint(0, self.n)/self.n,
                randint(0, self.n)/self.n,
                randint(0, self.n)/self.n
            )
        return self.sim
class MonteCarlo(Simulation):
    def __init__(self, n, j):
        super().__init__(n)
        self.j = j
        self.samples = {}
    def run(self):
        for k in range(self.j):
            simulation = Simulation(self.n)
            self.samples[k] = simulation.run()
        return self.samples
    def estimate(self):
        count = 0
        for k in self.samples:
            # FIX: iterate over values, not keys
            for point in self.samples[k].values():
                x, y, z = point
                if x**2 + y**2 + z**2 <= 1:
                    count += 1
        return count / (len(self.samples) * self.n) * 6
#Use reasonable numbers (or your computer will die)
Sim_1 = MonteCarlo(1000000, 4)
Sim_1.run()
print(Sim_1.estimate())
Pi=3.14159265358979323
print(((Sim_1.estimate()-Pi)/Pi)*100, "%"  "\terror")