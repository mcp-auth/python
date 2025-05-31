"""
A simple Todo service for demonstration purposes.
Uses an in-memory list to store todos.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
import random
import string

class Todo:
    """Represents a todo item."""
    
    def __init__(self, id: str, content: str, owner_id: str, created_at: str):
        self.id = id
        self.content = content
        self.owner_id = owner_id
        self.created_at = created_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert todo to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "content": self.content,
            "ownerId": self.owner_id,
            "createdAt": self.created_at
        }


class TodoService:
    """A simple Todo service for demonstration purposes."""
    
    def __init__(self):
        self._todos: List[Todo] = []
    
    def get_all_todos(self, owner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all todos, optionally filtered by owner_id.
        
        Args:
            owner_id: If provided, only return todos owned by this user
            
        Returns:
            List of todo dictionaries
        """
        if owner_id:
            filtered_todos = [todo for todo in self._todos if todo.owner_id == owner_id]
            return [todo.to_dict() for todo in filtered_todos]
        return [todo.to_dict() for todo in self._todos]
    
    def get_todo_by_id(self, todo_id: str) -> Optional[Todo]:
        """
        Get a todo by its ID.
        
        Args:
            todo_id: The ID of the todo to retrieve
            
        Returns:
            Todo object if found, None otherwise
        """
        for todo in self._todos:
            if todo.id == todo_id:
                return todo
        return None
    
    def create_todo(self, content: str, owner_id: str) -> Dict[str, Any]:
        """
        Create a new todo.
        
        Args:
            content: The content of the todo
            owner_id: The ID of the user who owns this todo
            
        Returns:
            Dictionary representation of the created todo
        """
        todo = Todo(
            id=self._generate_id(),
            content=content,
            owner_id=owner_id,
            created_at=datetime.now().isoformat()
        )
        self._todos.append(todo)
        return todo.to_dict()
    
    def delete_todo(self, todo_id: str) -> Optional[Dict[str, Any]]:
        """
        Delete a todo by its ID.
        
        Args:
            todo_id: The ID of the todo to delete
            
        Returns:
            Dictionary representation of the deleted todo if found, None otherwise
        """
        for i, todo in enumerate(self._todos):
            if todo.id == todo_id:
                deleted_todo = self._todos.pop(i)
                return deleted_todo.to_dict()
        return None
    
    def _generate_id(self) -> str:
        """Generate a random ID for a todo."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) 
