from functools import wraps
from termcolor import colored
import time
import tracemalloc
import os

def timer(func):
    """Measure function execution time"""
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        if os.environ.get('DEBUG') == "True":
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            total_time = end_time - start_time
            print(colored(f'\nFinished running {func.__name__} in {total_time:.2f} seconds\n', "blue"))
            return result
        else:
            result = func(*args, **kwargs)
            return result
    return timeit_wrapper


def performance_check(func):
    """Measure performance of a function"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if os.environ.get('DEBUG') == "True":
            tracemalloc.start()
            start_time = time.perf_counter()
            res = func(*args, **kwargs)
            duration = time.perf_counter() - start_time
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            print(colored(f"\n\nFunction:             {func.__name__}"
                    f"\nMemory usage:         {current / 10**6:.6f} MB"
                    f"\nPeak memory usage:    {peak / 10**6:.6f} MB"
                    f"\nDuration:             {duration:.6f} sec"
                    f"\n{'-'*40}\n",
                    "blue"
            ))
            return res
        else:
            res = func(*args, **kwargs)
            return res
    return wrapper

def exception_filter(func):
  """ Wraps the decorated function in a try-catch. If function fails print out the exception. """
  @wraps(func)
  def wrapper(*args, **kwargs):
    try:
      res = func(*args, **kwargs)
      return res
    except Exception as e:
      print(colored(f"[ERROR] Exception in {func.__name__}: {e}", "red"))
  return wrapper
