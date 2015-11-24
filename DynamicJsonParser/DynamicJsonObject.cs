using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Dynamic;
using System.Collections;
using System.Web.Script.Serialization;
using System.Collections.ObjectModel;

namespace DynamicJsonParser
{
    /// <summary>
    /// Represents a JSON object that can be accessed using properties.
    /// </summary>
    public class DynamicJsonObject : DynamicObject, IEnumerable
    {
        private readonly IDictionary<string, object> mDictionary;

        /// <summary>
        /// Initializes a new instance of the <see cref="DynamicJsonObject"/> class.
        /// </summary> 
        /// <param name="dictionary">The dictionary.</param>
        public DynamicJsonObject(IDictionary<string, object> dictionary = null)
        {
            if (dictionary == null)
            {
                mDictionary = new Dictionary<string, object>();
            }
            else
            {
                mDictionary = dictionary;
            }
        }

        public IDictionary<string, object> Dictionary
        {
            get { return new ReadOnlyDictionary<string, object>(mDictionary); }
        }

        /// <summary>
        /// Returns a <see cref="System.String"/> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String"/> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            ToString(ref sb);
            return sb.ToString();
        }

        /// <summary>
        /// A helper method that generates a JSON string
        /// </summary>
        /// <param name="sb">The string builder.</param>
        private void ToString(ref StringBuilder sb)
        {
            sb.Append("{");

            var needComma = false;
            foreach (var pair in mDictionary)
            {
                if (needComma)
                {
                    sb.Append(",");
                }
                needComma = true;
                var value = pair.Value;
                var name = pair.Key;

                if (value == null)
                {
                    sb.AppendFormat("\"{0}\":\"{1}\"", name, "");
                }
                else
                {
                    sb.AppendFormat("\"{0}\":", name);
                    JavaScriptSerializer serializer = new JavaScriptSerializer();
                    serializer.RegisterConverters(new [] { new DynamicJsonObjectConverter() });
                    serializer.Serialize(value, sb);
                }
            }
            sb.Append("}");
        }

        /// <summary>
        /// If you try to get a value of a property not defined in the class, this method is called.
        /// Provides the implementation for operations that get member values. Classes derived from the <see cref="T:System.Dynamic.DynamicObject"/> class can override this method to specify dynamic behavior for operations such as getting a value for a property.
        /// </summary>
        /// <param name="binder">Provides information about the object that called the dynamic operation. The binder.Name property provides the name of the member on which the dynamic operation is performed. For example, for the Console.WriteLine(sampleObject.SampleProperty) statement, where sampleObject is an instance of the class derived from the <see cref="T:System.Dynamic.DynamicObject"/> class, binder.Name returns "SampleProperty". The binder.IgnoreCase property specifies whether the member name is case-sensitive.</param>
        /// <param name="result">The result of the get operation. For example, if the method is called for a property, you can assign the property value to <paramref name="result"/>.</param>
        /// <returns>
        /// true if the operation is successful; otherwise, false. If this method returns false, the run-time binder of the language determines the behavior. (In most cases, a run-time exception is thrown.)
        /// </returns>
        public override bool TryGetMember(GetMemberBinder binder, out object result)
        {
            if (!mDictionary.TryGetValue(binder.Name, out result))
            {
                result = null;
                return true;
            }

            var dictionary = result as IDictionary<string, object>;
            if (dictionary != null)
            {
                result = new DynamicJsonObject(dictionary);
                return true;
            }

            var arrayList = result as ArrayList;
            if (arrayList != null && arrayList.Count > 0)
            {
                if (arrayList[0] is IDictionary<string, object>)
                    result = new List<object>(arrayList.Cast<IDictionary<string, object>>().Select(x => new DynamicJsonObject(x)));
                else
                    result = new List<object>(arrayList.Cast<object>());
            }

            return true;
        }


        /// <summary>
        /// If you try to set a value of a property that is not defined in the class, this method is called.
        /// Provides the implementation for operations that set member values. Classes derived from the <see cref="T:System.Dynamic.DynamicObject"/> class can override this method to specify dynamic behavior for operations such as setting a value for a property.
        /// </summary>
        /// <param name="binder">Provides information about the object that called the dynamic operation. The binder.Name property provides the name of the member to which the value is being assigned. For example, for the statement sampleObject.SampleProperty = "Test", where sampleObject is an instance of the class derived from the <see cref="T:System.Dynamic.DynamicObject"/> class, binder.Name returns "SampleProperty". The binder.IgnoreCase property specifies whether the member name is case-sensitive.</param>
        /// <param name="value">The value to set to the member. For example, for sampleObject.SampleProperty = "Test", where sampleObject is an instance of the class derived from the <see cref="T:System.Dynamic.DynamicObject"/> class, the <paramref name="value"/> is "Test".</param>
        /// <returns>
        /// true if the operation is successful; otherwise, false. If this method returns false, the run-time binder of the language determines the behavior. (In most cases, a language-specific run-time exception is thrown.)
        /// </returns>
        public override bool TrySetMember(SetMemberBinder binder, object value)
        {
            mDictionary[binder.Name] = value;
            return true;
        }

        #region Enumeration

        IEnumerator IEnumerable.GetEnumerator()
        {
            return (IEnumerator)GetEnumerator();
        }

        /// <summary>
        /// Returns an enumerator that iterates through a collection.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Collections.IEnumerator"/> object that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator GetEnumerator()
        {
            foreach (var kv in mDictionary)
            {
                yield return kv;
            }
        }

        #endregion
    }
}
