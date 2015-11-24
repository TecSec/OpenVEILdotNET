using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DynamicJsonParser
{

    /// <summary>
    /// dynamic type implememnts specificity
    /// i.e. the most specific function call will be chosen at the runtime.
    /// RuntimeBinderException is thrown if appropriate type is not found.
    /// The exception can be avoided by implementing a function that accepts an object.
    /// </summary>
    public class Specificity
    {
        /// <summary>
        /// Since obj is a dynamic variable its type determined at runtime.
        /// 
        /// </summary>
        /// <param name="obj">The obj.</param>
        public static void printDynamic(dynamic obj)
        {
            print(obj);
        }

        /// <summary>
        /// This version of print is only called
        /// for an argument of type List<int>
        /// </summary>
        /// <param name="obj">The obj.</param>
        protected static void print(List<int> list)
        {
            foreach (var item in list)
            {
                Console.WriteLine(item);
            }
        }

        /// <summary>
        /// This version of print is called for any
        /// argument type other than List<int>,
        /// allowing us to avoid RuntimeBinderException
        /// for types other than List<int>
        /// </summary>
        /// <param name="obj">The obj.</param>
        protected static void print(object obj)
        {
            Console.WriteLine("I do not know how to print you");
        }

    }
}
