import cProfile

if __name__ == "__main__":
    cProfile.run("from .file_activity import main\nmain()", sort="tottime")
